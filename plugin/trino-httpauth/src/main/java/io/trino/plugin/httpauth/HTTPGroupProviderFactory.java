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
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import io.trino.spi.security.GroupProvider;
import io.trino.spi.security.GroupProviderFactory;

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashSet;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;

public class HTTPGroupProviderFactory
        implements GroupProviderFactory
{
    private static final String NAME = "http-groupprovider";
    private final Gson gson = new Gson();

    @Override
    public String getName()
    {
        return NAME;
    }

    @Override
    public GroupProvider create(Map<String, String> config)
    {
        String groupServiceUrl = config.get("http-groupprovider.endpoint");
        return new HttpGroupProvider(groupServiceUrl, gson);
    }

    public static class HttpGroupProvider
                implements GroupProvider
    {
        private final String groupServiceUrl;
        private final Gson gson;

        public HttpGroupProvider(String groupServiceUrl, Gson gson)
        {
            this.groupServiceUrl = groupServiceUrl;
            this.gson = gson;
        }

        @Override
        public Set<String> getGroups(String username)
        {
            try {
                // Create HTTP connection and send POST request
                URL url = new URL(groupServiceUrl);
                HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                connection.setRequestMethod("POST");
                connection.setRequestProperty("Content-Type", "application/json");
                connection.setDoOutput(true);

                // Construct the payload (username)
                JsonObject jsonInput = new JsonObject();
                jsonInput.addProperty("username", username);

                // Write the payload
                try (OutputStreamWriter writer = new OutputStreamWriter(connection.getOutputStream())) {
                    writer.write(gson.toJson(jsonInput));
                    writer.flush();
                }

                // Read response from the service
                StringBuilder response = new StringBuilder();
                try (Scanner scanner = new Scanner(connection.getInputStream())) {
                    while (scanner.hasNextLine()) {
                        response.append(scanner.nextLine());
                    }
                }

                // Parse the response into a JsonObject
                JsonObject responseObject = gson.fromJson(response.toString(), JsonObject.class);

                JsonArray groupsArray = responseObject.getAsJsonArray("groups");

                // Convert the JsonArray to a Set<String>
                Set<String> groups = new HashSet<>();
                for (int i = 0; i < groupsArray.size(); i++) {
                    groups.add(groupsArray.get(i).getAsString());
                }

                return groups;
            }
            catch (IOException e) {
                throw new RuntimeException("Failed to retrieve groups from the group service", e);
            }
        }
    }
}
