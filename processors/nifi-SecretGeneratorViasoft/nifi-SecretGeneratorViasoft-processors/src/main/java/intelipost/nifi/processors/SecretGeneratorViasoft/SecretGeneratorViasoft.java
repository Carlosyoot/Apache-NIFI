/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package intelipost.nifi.processors.SecretGeneratorViasoft;

import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.components.state.Scope;
import org.apache.nifi.components.state.StateManager;
import org.apache.nifi.components.state.StateMap;
import org.apache.nifi.flowfile.FlowFile;
import org.apache.nifi.logging.ComponentLog;
import org.apache.nifi.annotation.behavior.ReadsAttribute;
import org.apache.nifi.annotation.behavior.ReadsAttributes;
import org.apache.nifi.annotation.behavior.WritesAttribute;
import org.apache.nifi.annotation.behavior.WritesAttributes;
import org.apache.nifi.annotation.documentation.CapabilityDescription;
import org.apache.nifi.annotation.documentation.Tags;
import org.apache.nifi.processor.AbstractProcessor;
import org.apache.nifi.processor.ProcessContext;
import org.apache.nifi.processor.ProcessSession;
import org.apache.nifi.processor.ProcessorInitializationContext;
import org.apache.nifi.processor.Relationship;
import org.apache.nifi.processor.exception.ProcessException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@Tags({"viasoft", "jwt", "secret", "token"})
@CapabilityDescription("Gera uma chave secreta única e persistente usada para assinar tokens JWT. Pode forçar a criação de uma nova chave, invalidando as anteriores.")
@ReadsAttributes({@ReadsAttribute(attribute="", description="")})
@WritesAttributes({@WritesAttribute(attribute="secret.key", description="A chave secreta gerada e persistida para assinatura de JWTs")})
public class SecretGeneratorViasoft extends AbstractProcessor {

    public static final PropertyDescriptor FORCE_NEW_SECRET = new PropertyDescriptor
        .Builder().name("Forçar Nova Chave")
        .displayName("Forçar Nova Chave")
        .description("Se verdadeiro, uma nova secret key será gerada a cada execução, substituindo a existente.")
        .required(true)
        .allowableValues("true", "false")
        .defaultValue("false")
        .build();

    public static final Relationship REL_SUCCESS = new Relationship.Builder()
        .name("Sucesso")
        .description("Sucesso na geração ou recuperação da chave secreta.")
        .build();

    public static final Relationship REL_FAILURE = new Relationship.Builder()
        .name("Falha")
        .description("Falha na geração ou persistência da chave secreta.")
        .build();

    private List<PropertyDescriptor> descriptors;
    private Set<Relationship> relationships;

    @Override
    protected void init(final ProcessorInitializationContext context) {
        final List<PropertyDescriptor> descriptors = new ArrayList<>();
        descriptors.add(FORCE_NEW_SECRET);
        this.descriptors = Collections.unmodifiableList(descriptors);

        final Set<Relationship> relationships = new HashSet<>();
        relationships.add(REL_SUCCESS);
        relationships.add(REL_FAILURE);
        this.relationships = Collections.unmodifiableSet(relationships);
    }

    @Override
    public Set<Relationship> getRelationships() {
        return relationships;
    }

    @Override
    public List<PropertyDescriptor> getSupportedPropertyDescriptors() {
        return descriptors;
    }

    @Override
    public void onTrigger(final ProcessContext context, final ProcessSession session) throws ProcessException {
        FlowFile flowFile = session.get();
        if (flowFile == null) return;

        final ComponentLog logger = getLogger();
        final StateManager stateManager = context.getStateManager();
        final StateMap stateMap;

        try {
            stateMap = stateManager.getState(Scope.LOCAL);
            boolean forceNew = context.getProperty(FORCE_NEW_SECRET).getValue().equalsIgnoreCase("true");
            String secretKey = stateMap.get("secret.key");

            if (secretKey == null || forceNew) {
                secretKey = UUID.randomUUID().toString() + UUID.randomUUID().toString();

                final Map<String, String> newState = new HashMap<>();
                newState.put("secret.key", secretKey);

                stateManager.setState(newState, Scope.LOCAL);

                logger.info("Nova chave secreta gerada.");
            } else {
                logger.info("Chave secreta existente recuperada do estado.");
            }

            flowFile = session.putAttribute(flowFile, "secret.key", secretKey);
            session.transfer(flowFile, REL_SUCCESS);

        } catch (Exception e) {
            logger.error("Erro ao gerar ou recuperar chave secreta", e);
            session.transfer(flowFile, REL_FAILURE);
        }
    }
}