/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.trino.plugin.httpauth;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import io.trino.spi.security.AccessDeniedException;
import io.trino.spi.security.BasicPrincipal;
import io.trino.spi.security.HeaderAuthenticator;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.lang.reflect.Type;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.HashMap;
import java.util.List;

public class HTTPAuthenticator
        implements HeaderAuthenticator
{
    private final String authenticationEndpoint;

    public HTTPAuthenticator(String authenticationEndpoint)
    {
        this.authenticationEndpoint = authenticationEndpoint;
    }

    @Override
    public Principal createAuthenticatedPrincipal(Headers headers)
    {
        List<String> authHeaders = headers.getHeader("Authorization");

        if (authHeaders == null || authHeaders.isEmpty()) {
            throw new AccessDeniedException("Missing Authorization header");
        }

        String challenge = authHeaders.get(0);
        if (challenge == null) {
            throw new AccessDeniedException("Invalid or missing login or access token");
        }

        String user = validateChallenge(challenge);
        if (user == null) {
            throw new AccessDeniedException("Invalid or missing login or access token");
        }
        return new BasicPrincipal(user);
    }

    private String validateChallenge(String challenge)
    {
        try {
            URL url = new URL(authenticationEndpoint);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Authorization", challenge);
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setRequestProperty("Accept", "application/json");
            connection.setDoOutput(true);

            try (OutputStream os = connection.getOutputStream();
                    BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(os, StandardCharsets.UTF_8))) {
                writer.write("{}");
                writer.flush();
            }

            String user = null;
            int responseCode = connection.getResponseCode();
            if (responseCode == 200) {
                // Read the response
                BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8));
                StringBuilder response = new StringBuilder();
                String responseLine;
                while ((responseLine = br.readLine()) != null) {
                    response.append(responseLine.trim());
                }

                // Parse JSON response to HashMap using Gson
                Gson gson = new Gson();
                Type type = new TypeToken<HashMap<String, Object>>() {}.getType();
                HashMap<String, Object> responseMap = gson.fromJson(response.toString(), type);
                if (responseMap.containsKey("principal")) {
                    user = responseMap.get("principal").toString();
                }
            }
            else {
                System.out.println("Authentication failed. Response code: " + responseCode);
            }
            return user;
        }
        catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }
}
