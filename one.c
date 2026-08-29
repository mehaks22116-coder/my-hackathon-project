// -----------------------------------------------------------------------------
// EventGuard - Event Registration and Check-in Server
// 
// This service provides an API for checking email security breaches, 
// registering attendees, and handling QR-code based check-ins.
// It uses Mongoose for the web server, SQLite for data storage, and cJSON.
// -----------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uuid/uuid.h>
#include "mongoose.h"
#include "sqlite3.h"
#include <curl/curl.h>
#include "cJSON.h"

// Configuration constants
static const char *SERVER_URL = "http://localhost:8000";
sqlite3 *app_database;

// -----------------------------------------------------------------------------
// Database Initialization
// -----------------------------------------------------------------------------
void initialize_database() {
    int rc = sqlite3_open("eventguard.db", &app_database);
    
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(app_database));
        exit(1);
    }

    // Structured SQL for readability
    const char *setup_sql = 
        "CREATE TABLE IF NOT EXISTS attendees ("
        "   id TEXT PRIMARY KEY, "
        "   name TEXT, "
        "   email TEXT, "
        "   unique_token TEXT UNIQUE"
        ");"
        "CREATE TABLE IF NOT EXISTS checkins ("
        "   id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "   attendee_id TEXT UNIQUE, "
        "   checked_in_at DATETIME DEFAULT CURRENT_TIMESTAMP"
        ");";
    
    char *error_message = NULL;
    sqlite3_exec(app_database, setup_sql, 0, 0, &error_message);
    
    if (error_message) {
        fprintf(stderr, "Database initialization error: %s\n", error_message);
        sqlite3_free(error_message);
    } else {
        printf("Database initialized successfully.\n");
    }
}

// -----------------------------------------------------------------------------
// CURL Helpers (Prepared for future real API integration)
// -----------------------------------------------------------------------------
struct MemoryStruct { 
    char *memory; 
    size_t size; 
};

static size_t write_memory_callback(void *contents, size_t size, size_t nmemb, void *user_pointer) {
    size_t real_size = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)user_pointer;
    
    char *ptr = realloc(mem->memory, mem->size + real_size + 1);
    if (!ptr) {
        return 0; // Out of memory
    }
    
    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, real_size);
    mem->size += real_size;
    mem->memory[mem->size] = 0; // Null-terminate
    
    return real_size;
}

// -----------------------------------------------------------------------------
// API Endpoint Handlers
// -----------------------------------------------------------------------------

// POST /api/security/check
// Checks if an email has been part of a known data breach.
static void handle_breach_check(struct mg_connection *connection, struct mg_http_message *request) {
    cJSON *json_payload = cJSON_ParseWithLength(request->body.ptr, request->body.len);
    cJSON *email_field = cJSON_GetObjectItem(json_payload, "email");
    
    // Validate request body
    if (!email_field || !cJSON_IsString(email_field)) {
        mg_http_reply(connection, 400, "Content-Type: application/json\r\n", "{\"error\": \"Missing email\"}");
        cJSON_Delete(json_payload);
        return;
    }

    // MOCK RESPONSE: Used for UI/UX testing without needing a paid HIBP API key.
    // (In production, replace this with a libcurl call to HaveIBeenPwned).
    if (strstr(email_field->valuestring, "breached") != NULL) {
        const char *mock_breach_data = 
            "{\"breaches\": ["
            "   {\"Name\": \"Canva\", \"BreachDate\": \"2019-05-24\", \"DataClasses\": [\"Email addresses\", \"Passwords\", \"Usernames\"]}, "
            "   {\"Name\": \"LinkedIn\", \"BreachDate\": \"2012-05-05\", \"DataClasses\": [\"Email addresses\", \"Passwords\"]}"
            "]}";
        mg_http_reply(connection, 200, "Content-Type: application/json\r\n", mock_breach_data);
    } else {
        mg_http_reply(connection, 200, "Content-Type: application/json\r\n", "{\"breaches\": []}");
    }
    
    cJSON_Delete(json_payload);
}

// POST /api/events/register
// Registers a new attendee and generates a unique QR token for them.
static void handle_register(struct mg_connection *connection, struct mg_http_message *request) {
    cJSON *json_payload = cJSON_ParseWithLength(request->body.ptr, request->body.len);
    cJSON *name_field = cJSON_GetObjectItem(json_payload, "name");
    cJSON *email_field = cJSON_GetObjectItem(json_payload, "email");

    // Validate required fields
    if (!name_field || !email_field) {
        mg_http_reply(connection, 400, "", "{\"error\": \"Missing fields\"}");
        cJSON_Delete(json_payload); 
        return;
    }

    // Generate a secure, unique UUID token for the attendee's QR code
    uuid_t binary_uuid;
    char token[37];
    uuid_generate_random(binary_uuid);
    uuid_unparse_lower(binary_uuid, token);

    // Save attendee to database
    sqlite3_stmt *statement;
    const char *insert_query = "INSERT INTO attendees (id, name, email, unique_token) VALUES (?, ?, ?, ?)";
    
    sqlite3_prepare_v2(app_database, insert_query, -1, &statement, NULL);
    sqlite3_bind_text(statement, 1, token, -1, SQLITE_TRANSIENT); // Using token as ID for simplicity
    sqlite3_bind_text(statement, 2, name_field->valuestring, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 3, email_field->valuestring, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 4, token, -1, SQLITE_TRANSIENT);
    
    sqlite3_step(statement);
    sqlite3_finalize(statement);

    // Build and send the success response
    char response_buffer[256];
    snprintf(response_buffer, sizeof(response_buffer), 
             "{\"status\": \"success\", \"token\": \"%s\", \"name\": \"%s\"}", 
             token, name_field->valuestring);
             
    mg_http_reply(connection, 200, "Content-Type: application/json\r\n", response_buffer);
    cJSON_Delete(json_payload);
}

// POST /api/events/checkin
// Processes an attendee check-in using their unique token.
static void handle_checkin(struct mg_connection *connection, struct mg_http_message *request) {
    cJSON *json_payload = cJSON_ParseWithLength(request->body.ptr, request->body.len);
    cJSON *token_field = cJSON_GetObjectItem(json_payload, "token");
    
    if (!token_field) { 
        mg_http_reply(connection, 400, "", "{\"error\": \"Missing token\"}"); 
        cJSON_Delete(json_payload); 
        return; 
    }

    sqlite3_stmt *lookup_statement;
    const char *lookup_query = "SELECT id, name FROM attendees WHERE unique_token = ?";
    
    sqlite3_prepare_v2(app_database, lookup_query, -1, &lookup_statement, NULL);
    sqlite3_bind_text(lookup_statement, 1, token_field->valuestring, -1, SQLITE_STATIC);
    
    // Check if the token belongs to a valid attendee
    if (sqlite3_step(lookup_statement) == SQLITE_ROW) {
        const unsigned char *attendee_id = sqlite3_column_text(lookup_statement, 0);
        const unsigned char *attendee_name = sqlite3_column_text(lookup_statement, 1);
        
        // Attempt to record the check-in
        sqlite3_stmt *insert_statement;
        const char *insert_query = "INSERT INTO checkins (attendee_id) VALUES (?)";
        
        sqlite3_prepare_v2(app_database, insert_query, -1, &insert_statement, NULL);
        sqlite3_bind_text(insert_statement, 1, (const char *)attendee_id, -1, SQLITE_STATIC);
        
        int execution_result = sqlite3_step(insert_statement);
        char response_buffer[256];
        
        if (execution_result == SQLITE_DONE) {
            // First time checking in
            snprintf(response_buffer, sizeof(response_buffer), 
                     "{\"status\": \"success\", \"attendee\": {\"name\": \"%s\"}}", 
                     attendee_name);
            mg_http_reply(connection, 200, "Content-Type: application/json\r\n", response_buffer);
            
        } else if (execution_result == SQLITE_CONSTRAINT) { 
            // Duplicate caught by the UNIQUE database constraint on attendee_id
            snprintf(response_buffer, sizeof(response_buffer), 
                     "{\"status\": \"duplicate\", \"attendee\": {\"name\": \"%s\"}}", 
                     attendee_name);
            mg_http_reply(connection, 409, "Content-Type: application/json\r\n", response_buffer);
        }
        
        sqlite3_finalize(insert_statement);
    } else {
        // Token was not found in the attendees table
        mg_http_reply(connection, 404, "Content-Type: application/json\r\n", "{\"error\": \"Invalid QR\"}");
    }
    
    sqlite3_finalize(lookup_statement);
    cJSON_Delete(json_payload);
}

// -----------------------------------------------------------------------------
// Server Router
// -----------------------------------------------------------------------------
static void route_requests(struct mg_connection *connection, int event, void *event_data, void *function_data) {
    if (event == MG_EV_HTTP_MSG) {
        struct mg_http_message *request = (struct mg_http_message *) event_data;
        
        // Route API requests to their specific handlers
        if (mg_http_match_uri(request, "/api/security/check")) {
            handle_breach_check(connection, request);
        } 
        else if (mg_http_match_uri(request, "/api/events/register")) {
            handle_register(connection, request);
        } 
        else if (mg_http_match_uri(request, "/api/events/checkin")) {
            handle_checkin(connection, request);
        } 
        else {
            // Serve frontend UI automatically for any unmatched routes
            struct mg_http_serve_opts options = { .root_dir = "." };
            mg_http_serve_dir(connection, request, &options);
        }
    }
}

// -----------------------------------------------------------------------------
// Main Application Entry
// -----------------------------------------------------------------------------
int main(void) {
    initialize_database();
    
    struct mg_mgr event_manager;
    mg_mgr_init(&event_manager);
    
    // Start listening on the specified port
    mg_http_listen(&event_manager, SERVER_URL, route_requests, NULL);
    printf("EventGuard server running on %s\n", SERVER_URL);
    
    // Main event loop
    for (;;) {
        mg_mgr_poll(&event_manager, 1000);
    }
    
    // Cleanup (Though practically unreachable in this infinite loop)
    mg_mgr_free(&event_manager);
    return 0;
}