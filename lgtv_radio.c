#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <curl/curl.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/select.h>

#define RESPONSE_BUF_SIZE 2048
#define MAX_URL_SIZE 1024
#define MAX_DEVICES 16
#define MULTICAST_IP "239.255.255.250"
#define MULTICAST_PORT 1900

int dlna_scan() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return 1;

    // Set up local broadcast target
    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(MULTICAST_PORT);
    target.sin_addr.s_addr = inet_addr(MULTICAST_IP);

    // Standard UPnP Media Renderer search string
    const char *search_msg = 
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 2\r\n"
        "ST: urn:schemas-upnp-org:service:AVTransport:1\r\n\r\n";

    // Broadcast the query over the network
    sendto(sock, search_msg, strlen(search_msg), 0, (struct sockaddr *)&target, sizeof(target));

    printf("Scanning local network for DLNA Media Renderers...\n");

    // Define variables to preserve device counts and handle deduplication
    char discovered_ips[MAX_DEVICES][16];
    int device_count = 0;

    fd_set fds;
    struct timeval tv;
    char buffer[RESPONSE_BUF_SIZE];

    // Loop continuously until the select timeout completely drains
    while (1) {
        FD_ZERO(&fds);
        FD_SET(sock, &fds);
        
        // Refresh timeout every iteration (re-allocates 1 second for subsequent responses)
        tv.tv_sec = 2;
        tv.tv_usec = 0;

        int activity = select(sock + 1, &fds, NULL, NULL, &tv);
        
        if (activity == 0) {
            printf("\nScan complete.\n");
            break; // Timeout hit, safely terminate scanning loop
        } else if (activity < 0) {
            perror("Select error");
            break;
        }

        // A packet is waiting on the wire
        struct sockaddr_in responder;
        socklen_t len = sizeof(responder);
        int n = recvfrom(sock, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&responder, &len);
        
        if (n > 0) {
            buffer[n] = '\0';
            char *ip_str = inet_ntoa(responder.sin_addr);

            // Simple deduplication: Check if we already processed this IP in this wave
            int duplicate = 0;
            for (int i = 0; i < device_count; i++) {
                if (strcmp(discovered_ips[i], ip_str) == 0) {
                    duplicate = 1;
                    break;
                }
            }
            if (duplicate) continue; // Skip printing if the device sent multiple headers

            // Save the unique device IP
            if (device_count < MAX_DEVICES) {
                strncpy(discovered_ips[device_count++], ip_str, 16);
            }

            printf("\n");
            printf("[Device Discovered] IP Address: %s\n", ip_str);
            printf("------------------------------------------------\n");
            
            // Extract the Location Info
            char *loc = strstr(buffer, "LOCATION:");
            if (!loc) loc = strstr(buffer, "location:");
            if (!loc) loc = strstr(buffer, "Location:");
            
            // Extract the Server Info to identify your brand mappings
            char *srv = strstr(buffer, "SERVER:");
            if (!srv) srv = strstr(buffer, "server:");
            if (!srv) srv = strstr(buffer, "Server:");

	    if (!loc || !srv) {
                printf("\n=== [ALERT] Anomalous Packet Caught (Missing standard headers) ===\n");
                printf("%s\n", buffer);
	    }
	    else {
                char *end;
		if ((end = strpbrk(loc, "\r\n"))) *end = 0;
		if ((end = strpbrk(srv, "\r\n"))) *end = 0;
                printf("%s\n", loc);
                printf("%s\n", srv);

                if (strstr(srv, "LGE WebOS") || strstr(srv, "webOS")) {
                    printf(" -> Action: LG TV matched. WS Port: 3001\n");
                } else if (strstr(srv, "Tizen") || strstr(srv, "Samsung")) {
                    printf(" -> Action: Samsung TV matched. WS Port: 8002\n");
                } else if (strstr(srv, "Roku")) {
                    printf(" -> Action: Roku TV matched. Control Port: 8060\n");
                }
            }
            printf("------------------------------------------------\n");
        }
    }

    close(sock);
    return 0;
}


void send_raw_ws_frame(CURL *curl, const char *payload) {
    size_t len = strlen(payload);
    size_t max_frame_size = len + 10;
    unsigned char *ws_packet = malloc(max_frame_size);
    if (!ws_packet) return;

    int header_len = 0;
    ws_packet[header_len++] = 0x81; 

    if (len < 126) {
        ws_packet[header_len++] = 0x80 | len; 
    } else {
        ws_packet[header_len++] = 0x80 | 126;
        ws_packet[header_len++] = (len >> 8) & 0xFF;
        ws_packet[header_len++] = len & 0xFF;
    }

    ws_packet[header_len++] = 0x00;
    ws_packet[header_len++] = 0x00;
    ws_packet[header_len++] = 0x00;
    ws_packet[header_len++] = 0x00;

    memcpy(ws_packet + header_len, payload, len);
    size_t total_frame_len = header_len + len;

    size_t bytes_written;
    curl_easy_send(curl, ws_packet, total_frame_len, &bytes_written);
    free(ws_packet);
}

#define DIG_DEEPER 1
//#define DIG_DEEPER_RAW_RECV 1

#ifdef DIG_DEEPER
// Check if a URL ends with or contains a playlist extension (.pls or .m3u).
// HLS .m3u8 files look like .m3u but actually rotate streams in 5s increments so leave it alone.
int is_playlist_url(const char *url) {
    // 1. Instantly find the LAST dot in the URL string
    const char *dot = strrchr(url, '.');
    if (!dot) return 0; // No extension found at all
    dot++; // Move past the '.' character

    // 2. Count chars in ext.  Stops at slash, ?, &, CR, or NL.
    size_t ext_len = strcspn(dot, "/?&\r\n");

    // 3. Perform a safe, bounded, case-insensitive comparison
    if ((ext_len == 3 && strncasecmp(dot, "pls", 3) == 0) ||
        (ext_len == 3 && strncasecmp(dot, "m3u", 3) == 0)) {
        return 1;
    }
    return 0;
}

// Universal, sanitized parser for .pls, .m3u files. 
int extract_raw_stream(const char* playlist_buf, char* raw_url_out, size_t max_len) {
    char *url_start = strstr(playlist_buf, "http://");
    if (!url_start) url_start = strstr(playlist_buf, "https://");
    if (url_start) {
        char *end = strpbrk(url_start, "\r\n");
        if (end) *end = '\0';
        snprintf(raw_url_out, max_len, "%s", url_start);
        // SANITATION CHECK: Strip inline trailing whitespace or .m3u comment flags |
        end = strpbrk(raw_url_out, " |");
        if (end) *end = '\0';
        return 1; // Clean stream URL extracted successfully!
    }
    return 0; // No valid stream URL found
}

#ifndef DIG_DEEPER_RAW_RECV
// Small temporary container for the static stack buffer download tracker
struct StaticDownloadTracker {
    char *buffer;
    size_t max_size;
    size_t current_size;
};

// Safe memory callback that completely prevents dynamic reallocations
static size_t static_write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct StaticDownloadTracker *tracker = (struct StaticDownloadTracker *)userp;

    // HARD BOUNDARY ENFORCEMENT FOR THE ZIPIT Z2:
    // If the data over the air exceeds our 2K buffer size, truncate and stop immediately.
    if (tracker->current_size + realsize >= tracker->max_size) {
        printf("[WARNING] Playlist file truncated at safety boundary.\n");
        return 0; // Returning 0 forces libcurl to abort the transfer cleanly
    }

    memcpy(&(tracker->buffer[tracker->current_size]), contents, realsize);
    tracker->current_size += realsize;
    tracker->buffer[tracker->current_size] = '\0'; // Insures strict string termination

    return realsize;
}

int download_playlist(CURL *curl, const char *url, char *output_buf, size_t max_size) {
    CURLcode res;
    struct StaticDownloadTracker tracker;

    tracker.buffer = output_buf;
    tracker.max_size = max_size;
    tracker.current_size = 0;
    memset(output_buf, 0, max_size);

    // Standard high-level HTTP configurations
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L); // Automatically follows 301/302 redirects
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 4L);         // Strict 4-second timeout limit
    
    // Bind our strict static download tracker
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, static_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&tracker);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "dlnaplay/1.5");

    res = curl_easy_perform(curl);

    if (res == CURLE_OK) {
        long response_code;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        if (response_code == 200 && tracker.current_size > 0) {
            return 1; // Download succeeded, string is ready to be parsed by extract_raw_stream!
        }
        printf("[ERROR] HTTP Server responded with code: %ld\n", response_code);
    } else {
        printf("[ERROR] libcurl fetch failed: %s\n", curl_easy_strerror(res));
    }

    return 0;
}
#else // DIG_DEEPER_RAW_RECV
// 1. Reusable raw receiver loop that fits perfectly inside your existing design
int raw_socket_recv(CURL *curl, char *output_buf, size_t max_size) {
    size_t total_read = 0;
    size_t bytes_read = 0;
    CURLcode res;

    do {
        res = curl_easy_recv(curl, output_buf + total_read, max_size - total_read - 1, &bytes_read);
        if (res == CURLE_OK && bytes_read > 0) {
            total_read += bytes_read;
        }
        if (total_read >= max_size - 1) break;
    } while (res == CURLE_OK && bytes_read > 0);

    output_buf[total_read] = '\0'; // Strict string termination
    return (total_read > 0);
}
#endif // DIG_DEEPER_RAW_RECV
#endif // DIG_DEEPER

/* ============================================================================
 * LG WEBOS REFERENCE BLOCK FOR COMPANION FEATURES
 * Use these strings to expand the Zipit Z2 layout drivers in the future.
 * 
 * NOTE: Expanding permissions requires deleting the existing client key token
 * on the Zipit Z2 to force a fresh on-screen pairing authorization prompt.
 * ============================================================================
 */

/*
 * 1. UNIFIED REGISTRATION MANIFEST (Unlocks all features discussed)
 * "payload":{"manifest":{"permissions":["LAUNCH","CONTROL_AUDIO","MEDIA_CONTROL","CONTROL_POWER"]}}
 */

/*
 * 2. MEDIA CONTROL PAYLOADS (Requires "MEDIA_CONTROL" permission)
 * 
 * PAUSE AUDIO:
 * "{\"type\":\"request\",\"id\":\"zip_auth\",\"uri\":\"ssap://media.controls/pause\"}"
 * 
 * RESUME/UNPAUSE AUDIO:
 * "{\"type\":\"request\",\"id\":\"zip_auth\",\"uri\":\"ssap://media.controls/play\"}"
 * 
 * TRACK REWIND (Static MP3 files only):
 * "{\"type\":\"request\",\"id\":\"zip_auth\",\"uri\":\"ssap://media.controls/rewind\"}"
 * 
 * TRACK FAST FORWARD (Static MP3 files only):
 * "{\"type\":\"request\",\"id\":\"zip_auth\",\"uri\":\"ssap://media.controls/fastForward\"}"
 */

/*
 * 3. SCREEN DISCONNECT PAYLOADS (Requires "CONTROL_POWER" permission)
 * Closes the OLED panel to save energy during audio streaming, remote wakes it up.
 * 
 * BLANK PANEL SCREEN (Leaves audio running):
 * "{\"type\":\"request\",\"id\":\"zip_auth\",\"uri\":\"ssap://com.webos.service.tvpower/power/turnOffScreen\"}"
 * 
 * WAKE PANEL SCREEN:
 * "{\"type\":\"request\",\"id\":\"zip_auth\",\"uri\":\"ssap://com.webos.service.tvpower/power/turnOnScreen\"}"
 */

/*
 * 4. VOLUME & MUTE PAYLOADS (Requires "CONTROL_AUDIO")
 * 
 * SET DIRECT VOLUME / MUTE VIA ZERO:
 * Pass the integer target variable into %d using snprintf() (0 = Absolute Mute).
 * "{\"type\":\"request\",\"id\":\"zip_auth\",\"uri\":\"ssap://audio/setVolume\",\"payload\":{\"volume\":%d}}"
 * 
 * ALTERNATIVE: NATIVE MUTE STATE TOGGLE (True/False):
 * Forcefully sets the TV's native software mute state. Pass true or false.
 * "{\"type\":\"request\",\"id\":\"zip_auth\",\"uri\":\"ssap://audio/setMute\",\"payload\":{\"mute\":true}}"
 */

char *get_key(char * parsed_string) {
    static char extracted_key[64];

    memset(extracted_key, 0, sizeof(extracted_key));
    if (parsed_string) {
        for (size_t i = 0; parsed_string[i] != '\0'; i++) {
            if (parsed_string[i] >= 'A' && parsed_string[i] <= 'Z') {
                parsed_string[i] = parsed_string[i] + 32;
            }
        }

        char *key_tag = strstr(parsed_string, "client-key");
        if (key_tag) {
            if (sscanf(key_tag, "client-key\":\"%32[0-9a-f]", extracted_key) == 1) {
                printf("\n==================================================\n");
                printf("PAIRING KEY RETRIEVED: \n");
                printf("%s\n", extracted_key);
                printf("==================================================\n\n");
            } else {
                fprintf(stderr, "[ERROR] String layout matched key_tag but sscanf parsing rules failed.\n");
            }
        } else {
            fprintf(stderr, "[ERROR] key_tag pattern missing from response layout string:\n%s\n", parsed_string);
        }
    }
    return extracted_key;
}

int main(int argc, char *argv[]) {
    if (argc != 2 && argc != 4) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  IP Scan Mode: %s SCAN\n", argv[0]);
        fprintf(stderr, "  Pairing Mode: %s <TV_IP>\n", argv[0]);
        fprintf(stderr, "  Control Mode: %s <TV_IP> <PAIRING_KEY> <COMMAND>\n", argv[0]);
	fprintf(stderr, "  <COMMAND> = <STREAM_URL> | STOP | VOL+ | VOL-\n");
        //fprintf(stderr, "  <COMMAND> = <STREAM_URL> | STOP | VOL+ | VOL- | PAUSE | PLAY\n");
	
        return 1;
    }

    if (strcasecmp(argv[1], "SCAN") == 0) {
        return dlna_scan();  // If 1st arg is "SCAN" or "scan" then do dlna_scan()
    }

    const char *tv_ip = argv[1];
    const char *pairing_key = "";
    const char *stream_url = "";
    int has_key = 0;

    if (argc == 4) {
        pairing_key = argv[2];
        stream_url = argv[3];
        has_key = (strcasecmp(pairing_key, "NONE") != 0);
    }

    int is_stop_cmd = (strcasecmp(stream_url, "STOP") == 0);
    int is_vol_up   = (strcasecmp(stream_url, "VOL+") == 0);
    int is_vol_down = (strcasecmp(stream_url, "VOL-") == 0);
    //int is_pause = (strcasecmp(stream_url, "PAUSE") == 0);
    //int is_play = (strcasecmp(stream_url, "PLAY") == 0);

    int is_wake_up = (strcasecmp(stream_url, "WAKE") == 0);
    int is_stream_cmd = !(is_stop_cmd || is_vol_up || is_vol_down || is_wake_up);
    
    char tv_url[256];
    snprintf(tv_url, sizeof(tv_url), "https://%s:3001/", tv_ip);

    printf("[DEBUG] Target TV IP Address: %s\n", tv_ip);

    curl_global_init(CURL_GLOBAL_ALL);
    
#ifdef DIG_DEEPER
    if (is_playlist_url(stream_url)) {
        printf("[DEBUG] Playlist container detected.  Downloading...\n");
	char resolved_url[MAX_URL_SIZE];
	memset(resolved_url, 0, sizeof(resolved_url));
	    
        CURL *playlist_curl = curl_easy_init();
        if (!playlist_curl) {
            fprintf(stderr, "[ERROR] Failed to initialize playlist curl object.\n");
        }
	else {
            char response_buf[RESPONSE_BUF_SIZE];
#ifndef DIG_DEEPER_RAW_RECV
            if (download_playlist(playlist_curl, stream_url, response_buf, RESPONSE_BUF_SIZE)) {
                if (extract_raw_stream(response_buf, resolved_url, MAX_URL_SIZE)) {
                    stream_url = strdup(resolved_url);
                    printf("[DEBUG] New stream URL = %s\n", stream_url);
                }
                else {
                    printf("[ERROR] No stream URL found in Playlist\n");
                }
            }
#else // DIG_DEEPER_RAW_RECV
            curl_easy_setopt(playlist_curl, CURLOPT_URL, stream_url);
            curl_easy_setopt(playlist_curl, CURLOPT_CONNECT_ONLY, 1L);
            curl_easy_setopt(playlist_curl, CURLOPT_CONNECTTIMEOUT, 3L);
            curl_easy_setopt(playlist_curl, CURLOPT_TIMEOUT, 5L);

            if (curl_easy_perform(playlist_curl) == CURLE_OK) {
                // Manually write a simple HTTP/1.0 request header
                char http_request[512];
                snprintf(http_request, sizeof(http_request),
                         "GET %s HTTP/1.0\r\nHost: localhost\r\nUser-Agent: dlnaplay/1.5\r\n\r\n", stream_url);

                size_t bytes_sent;
                curl_easy_send(playlist_curl, http_request, strlen(http_request), &bytes_sent);

                if (raw_socket_recv(playlist_curl, response_buf, RESPONSE_BUF_SIZE)) {
                    if (extract_raw_stream(response_buf, resolved_url, MAX_URL_SIZE)) {
                        stream_url = strdup(resolved_url);
                        printf("[DEBUG] New stream URL = %s\n", stream_url);
                    } else {
                        printf("[ERROR] No stream URL found in Playlist\n");
                    }
                }
		else
                    printf("[ERROR] raw_socket_recv failed\n");

	    }
#endif // DIG_DEEPER_RAW_RECV
            else {
                printf("[ERROR] Playlist download FAILED!\n");
            }

            // curl_easy_reset(playlist_curl); // This should be enough to reuse one curl handle.
            curl_easy_cleanup(playlist_curl);  // Or just cleanup and use a new curl handle.
	}
    }
#endif // DIG_DEEPER
    
    // =========================================================================
    //  Create a fresh clean TV master curl handle
    // =========================================================================
    // This handle is now guaranteed to be 100% unpolluted by internet HTTP states
    CURL *curl;
 WAKE_UP:    
    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "[ERROR] Failed to initialize TV curl object.\n");
        curl_global_cleanup();
        return 1;
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, tv_url);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1L);
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_NONE);

    // Enforce a hard 3-second limit for the raw TCP and TLS handshake negotiation.
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 3L);
    
    // Set a total operational ceiling timeout of 6 seconds for the entire script execution.
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 6L);
    
    printf("[DEBUG] Executing secure TLS Handshake via tiny-curl engine...\n");
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "[ERROR] Handshake failed: %s\n", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        return 1;
    }
    printf("[DEBUG] Secure TLS layer active. Transmitting manual upgrade headers...\n");

    char handshake[512];
    snprintf(handshake, sizeof(handshake),
             "GET / HTTP/1.1\r\n"
             "Host: %s:3001\r\n"
             "Upgrade: websocket\r\n"
             "Connection: Upgrade\r\n"
             "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
             "Sec-WebSocket-Version: 13\r\n\r\n", tv_ip);
    
    size_t bytes_written;
    curl_easy_send(curl, handshake, strlen(handshake), &bytes_written);

    char response_buf[RESPONSE_BUF_SIZE];
    size_t bytes_read = 0;
    
    do {
        res = curl_easy_recv(curl, response_buf, sizeof(response_buf) - 1, &bytes_read);
        if (res == CURLE_AGAIN) {
            usleep(10000); 
        }
    } while (res == CURLE_AGAIN);

    if (res == CURLE_OK && bytes_read > 0) {
        response_buf[bytes_read] = '\0';
        if (strstr(response_buf, "101 Switching Protocols") == NULL) {
            fprintf(stderr, "[ERROR] Handshake rejected by TV server. Response:\n%s\n", response_buf);
            curl_easy_cleanup(curl);
            return 1;
        }
	else {
	  // printf("[DEBUG] TV RSP:\n%s\n", response_buf);
	}
    }
    printf("[DEBUG] WebSocket handshake verified and approved.\n");

    // UNIFIED FIXED PAYLOAD: Streamlined to prevent C string escaping errors
    char auth_payload[RESPONSE_BUF_SIZE];
    if (has_key) {
        printf("[DEBUG] Submitting pre-authenticated validation token...\n");
        snprintf(auth_payload, sizeof(auth_payload),
                 "{"
                   "\"type\":\"register\","
                   "\"id\":\"zip_auth\","
                   "\"payload\":{"
                     "\"client-key\":\"%s\","
                     "\"manifest\":{"
                       "\"manifestVersion\":1,"
                       "\"permissions\":[\"LAUNCH\",\"CONTROL_AUDIO\"]"
                     "}"
                   "}"
                 "}", pairing_key);
    } else {
        printf("[DEBUG] Triggering permission prompt loop on TV screen...\n");
        snprintf(auth_payload, sizeof(auth_payload),
                 "{"
                   "\"type\":\"register\","
                   "\"id\":\"zip_auth\","
                   "\"payload\":{"
                     "\"forcePairing\":false,"
                     "\"pairingType\":\"PROMPT\","
                     "\"manifest\":{"
                       "\"manifestVersion\":1,"
                       "\"permissions\":[\"LAUNCH\",\"CONTROL_AUDIO\"]"
                     "}"
                   "}"
                 "}");
    }
    
    send_raw_ws_frame(curl, auth_payload);
    
    printf("[DEBUG] Waiting for TV to authorize secure session token...\n");

    int loop_running = 1;
    int registered_confirmed = 0;

    // Define a zero-dependency 65-second time ceiling for human interaction
    // (65 seconds * 10 iterations per second = 650 max retries)
    int elapsed_cycles = 0;
    const int MAX_PAIRING_CYCLES = 650; // The TV will timeout Accept/Cancel at 60 secs.

    do {
        res = curl_easy_recv(curl, response_buf, sizeof(response_buf) - 1, &bytes_read);
	// Handle the half-open socket / idle loop safely
        if (res == CURLE_AGAIN) {
            elapsed_cycles++;
            if (elapsed_cycles > MAX_PAIRING_CYCLES) {
                fprintf(stderr, "[ERROR] Human pairing window timed out (65s ceiling reached).\n");
                loop_running = 0;
                break;
            }
            usleep(100000); // Sleep 100ms per cycle to keep Z2 CPU usage at 0%
            continue;
        }
        
        if (res == CURLE_OK && bytes_read > 2) {
            response_buf[bytes_read] = '\0';
            char *json_segment = response_buf + 2;
            
            printf("[DEBUG] TV FRAME: %s\n", json_segment);

            // Explicit Error Check: TV sent a refusal frame before disconnecting
            if (strstr(json_segment, "\"error\"") || strstr(json_segment, "denied")) {
                fprintf(stderr, "[ERROR] Pairing explicitly rejected by user on-screen.\n");
                loop_running = 0;
                break;
            }
	    
            if (!has_key && (strstr(json_segment, "client-key") != NULL || strstr(json_segment, "\"registered\"") != NULL)) {
                pairing_key = get_key(json_segment);
                if (strlen(stream_url)) { // Try again with KEY if stream url supplied with "NONE" key.
		    curl_easy_reset(curl); 
		    curl_easy_cleanup(curl);
		    has_key = 1;
		    goto WAKE_UP;
		}
                loop_running = 0;
            }
            
            if (has_key && strstr(json_segment, "\"registered\"") != NULL) {
                printf("[DEBUG] Handshake confirmed! TV has officially registered this token session.\n");
                registered_confirmed = 1;
                loop_running = 0; 
            }
            else if (strstr(json_segment, "Try Again Later") != NULL) {
                loop_running = 0; 
	    }	      
        } else if (res != CURLE_OK) {
            fprintf(stderr, "[ERROR] Network stream read fault code: %s\n", curl_easy_strerror(res));
            loop_running = 0;
        }
    } while (loop_running);

    // Give webOS .5 sec to finalize the session token authorization before app launch.
    // (avoids a 401 error)
    //usleep(250000);
    usleep(500000);
    //usleep(1250000);

    // 3. Transmit Play or Stop Command String
    if (strlen(stream_url) > 0 && registered_confirmed) {
        char cmd_payload[RESPONSE_BUF_SIZE];
        if (is_stop_cmd) {
            printf("[DEBUG] Sending browser closure application payload...\n");
            snprintf(cmd_payload, sizeof(cmd_payload),
                     "{\"type\":\"request\",\"id\":\"zip_close\",\"uri\":\"ssap://system.launcher/close\","
                     "\"payload\":{\"id\":\"com.webos.app.browser\"}}");
        } else if (is_vol_up) {
            printf("[DEBUG] Sending relative Volume Up command to eARC soundbar...\n");
            // Emulates pressing the physical Vol+ remote button over HDMI-CEC
            snprintf(cmd_payload, sizeof(cmd_payload),
                     "{\"type\":\"request\",\"id\":\"zip_auth\",\"uri\":\"ssap://audio/volumeUp\"}");
                     
        } else if (is_vol_down) {
            printf("[DEBUG] Sending relative Volume Down command to eARC soundbar...\n");
            // Emulates pressing the physical Vol- remote button over HDMI-CEC
            snprintf(cmd_payload, sizeof(cmd_payload),
                     "{\"type\":\"request\",\"id\":\"zip_auth\",\"uri\":\"ssap://audio/volumeDown\"}");
#if 0
        } else if (is_pause) {
            printf("[DEBUG] Sending media Pause command to target layout...\n");
            // Issues a standard SSAP playback pause instruction to the active media player
            snprintf(cmd_payload, sizeof(cmd_payload),
                     "{\"type\":\"request\",\"id\":\"zip_auth\",\"uri\":\"ssap://media.controls/pause\"}");
	} else if (is_play) {
	    printf("[DEBUG] Sending media Play command to target layout...\n");
	    // Issues a standard SSAP playback play instruction to the active media player
	    snprintf(cmd_payload, sizeof(cmd_payload),
		     "{\"type\":\"request\",\"id\":\"zip_auth\",\"uri\":\"ssap://media.controls/play\"}");
#endif	    
	} else {
            printf("[DEBUG] Sending browser stream audio launch payload...\n");
            snprintf(cmd_payload, sizeof(cmd_payload),
                     "{"
                       "\"type\":\"request\","
                       "\"id\":\"zip_auth\","
                       "\"uri\":\"ssap://system.launcher/launch\","
                       "\"payload\":{"
                         "\"id\":\"com.webos.app.browser\","
                         "\"params\":{"
                           "\"target\":\"%s\""
                         "}"
                       "}"
                     "}", stream_url);
        }

        send_raw_ws_frame(curl, cmd_payload);
        printf("[DEBUG] Program commands successfully sent to the network pipeline.\n");
        
        printf("[DEBUG] Entering final blocking execution loop. Waiting for TV acknowledgment...\n");
        int wait_for_ack = 1;
        int loop_count = 0;
        do {
            res = curl_easy_recv(curl, response_buf, sizeof(response_buf) - 1, &bytes_read);
            if (res == CURLE_AGAIN) {
                usleep(50000);
                loop_count++;
                if (loop_count > 80) { wait_for_ack = 0; }
                continue;
            }
            if (res == CURLE_OK && bytes_read > 2) {
                response_buf[bytes_read] = '\0';
                char *tv_msg = response_buf + 2;
                printf("\n--------------------------------------------------\n");
                printf("[RAW TV CONFIRMATION FRAME RECEIVED]:\n%s\n", tv_msg);
                printf("--------------------------------------------------\n\n");
                if (strstr(tv_msg, "returnValue") != NULL || strstr(tv_msg, "error") != NULL) {
                    wait_for_ack = 0; 
                }
            } else if (res != CURLE_OK) {
                wait_for_ack = 0;
            }
        } while (wait_for_ack);
    }

    curl_easy_cleanup(curl);
    curl_global_cleanup();

    return 0;
}
