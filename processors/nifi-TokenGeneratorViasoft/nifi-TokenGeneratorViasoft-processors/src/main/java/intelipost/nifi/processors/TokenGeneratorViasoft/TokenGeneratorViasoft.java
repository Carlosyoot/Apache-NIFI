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
package intelipost.nifi.processors.TokenGeneratorViasoft;

import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.expression.ExpressionLanguageScope;
import org.apache.nifi.flowfile.FlowFile;
import org.apache.nifi.annotation.behavior.ReadsAttribute;
import org.apache.nifi.annotation.behavior.ReadsAttributes;
import org.apache.nifi.annotation.behavior.WritesAttribute;
import org.apache.nifi.annotation.behavior.WritesAttributes;
import org.apache.nifi.annotation.lifecycle.OnScheduled;
import org.apache.nifi.annotation.documentation.CapabilityDescription;
import org.apache.nifi.annotation.documentation.SeeAlso;
import org.apache.nifi.annotation.documentation.Tags;
import org.apache.nifi.processor.AbstractProcessor;
import org.apache.nifi.processor.ProcessContext;
import org.apache.nifi.processor.ProcessSession;
import org.apache.nifi.processor.ProcessorInitializationContext;
import org.apache.nifi.processor.Relationship;
import org.apache.nifi.processor.util.StandardValidators;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@Tags({"security","token","provider","auth"})
@CapabilityDescription("Executa o processo gerando um Token com expiração e propriedades adicionais. Permite propriedades extras para navegação de dados sensíveis")
@SeeAlso({})
@ReadsAttributes({
    @ReadsAttribute(attribute = "jwt.*", description = "Atributos opcionais usados como claims no token JWT")
})
@WritesAttributes({@WritesAttribute(attribute="", description="")})
public class TokenGeneratorViasoft extends AbstractProcessor {

    public static final PropertyDescriptor TOKEN_EXPIRATION = new PropertyDescriptor
    .Builder().name("Token Expiration")
    .displayName("Expiração do Token (ms)")
    .description("Tempo de expiração do token em segundos após a emissão.")
    .required(true)
    .defaultValue("600") 
    .addValidator(StandardValidators.LONG_VALIDATOR)
    .build();

    @Override
    public PropertyDescriptor getSupportedDynamicPropertyDescriptor(final String propertyName) {
    return new PropertyDescriptor.Builder()
        .name(propertyName)
        .description("Propriedade dinâmica que será usada como claim JWT. O valor pode conter expressões como ${atributo}.")
        .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
        .dynamic(true)
        .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
        .required(false)
        .build();
}


    public static final Relationship REL_SUCCESS  = new Relationship.Builder()
        .description("Sucesso no processo de geração de um token jwt. O mesmo será posto em um atributo chamado token.code")
        .name("Sucesso")
        .build();

    public static final Relationship REL_FAILURE = new Relationship.Builder()
        .description("Falha no processo de geração do token jwt.")
        .name("Falha")
        .build();

    private List<PropertyDescriptor> descriptors;

    private Set<Relationship> relationships;

    @Override
    protected void init(final ProcessorInitializationContext context) {
        descriptors = new ArrayList<>();
        descriptors.add(TOKEN_EXPIRATION);
        descriptors = Collections.unmodifiableList(descriptors);

        relationships = new HashSet<>();
        relationships.add(REL_SUCCESS);
        relationships.add(REL_FAILURE);
        relationships = Collections.unmodifiableSet(relationships);
    }

    @Override
    public Set<Relationship> getRelationships() {
        return this.relationships;
    }

    @Override
    public final List<PropertyDescriptor> getSupportedPropertyDescriptors() {
        return descriptors;
    }

    @OnScheduled
    public void onScheduled(final ProcessContext context) {

    }

    @Override
    public void onTrigger(final ProcessContext context, final ProcessSession session) {
    FlowFile flowFile = session.get();
    if (flowFile == null) {
        return;
    }

    try {
        long expirationSecs = context.getProperty(TOKEN_EXPIRATION)
            .evaluateAttributeExpressions(flowFile)
            .asLong();

        Date now = new Date();
        Date expiration = new Date(now.getTime() + (expirationSecs * 1000));

        // Inicializa claims com padrão fixo
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
            .issuer("Token Agent")
            .issueTime(now)
            .expirationTime(expiration)
            .claim(getIdentifier(), expiration); // opcional: nome do processor como claim

        Map<String, String> atributosToken = new HashMap<>();

        // Processa propriedades dinâmicas como claims e atributos
        for (Map.Entry<PropertyDescriptor, String> entry : context.getProperties().entrySet()) {
            PropertyDescriptor descriptor = entry.getKey();

            if (descriptor.isDynamic()) {
                String propName = descriptor.getName(); // ex: email
                String value = context.getProperty(descriptor)
                    .evaluateAttributeExpressions(flowFile)
                    .getValue();

                if (value != null) {
                    claimsBuilder.claim(propName, value); // Claim no JWT (sem Token.)
                    atributosToken.put("Token." + propName, value); // Atributo Token.email etc.
                }
            }
        }

        // Constrói claims
        JWTClaimsSet claims = claimsBuilder.build();

        // Gera e assina o token
        String secret = UUID.randomUUID().toString() + UUID.randomUUID().toString();
        byte[] sharedSecret = secret.getBytes(StandardCharsets.UTF_8);
        JWSSigner signer = new MACSigner(sharedSecret);

        JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
        SignedJWT signedJWT = new SignedJWT(header, claims);
        signedJWT.sign(signer);

        String token = signedJWT.serialize();

        // Adiciona atributos padrão
        atributosToken.put("Token.id", token);
        atributosToken.put("Token.data", now.toInstant().toString());
        atributosToken.put("Token.exp", expiration.toInstant().toString());

        // Aplica atributos ao FlowFile
        flowFile = session.putAllAttributes(flowFile, atributosToken);

        session.transfer(flowFile, REL_SUCCESS);

    } catch (Exception e) {
        getLogger().error("Erro ao gerar token JWT", e);
        session.transfer(flowFile, REL_FAILURE);
    }
} 

   
}

