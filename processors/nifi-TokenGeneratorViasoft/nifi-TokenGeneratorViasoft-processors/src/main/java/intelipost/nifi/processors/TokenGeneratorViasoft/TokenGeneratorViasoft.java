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
import org.apache.nifi.logging.ComponentLog;
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
import org.apache.nifi.processor.exception.ProcessException;
import org.apache.nifi.processor.util.StandardValidators;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jose.crypto.RSASSASigner;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Tags({"security","token","provider","auth","viasoft"})
@CapabilityDescription("Executa o processo gerando um Token com expiração e propriedades adicionais. Permite propriedades extras para navegação de dados sensíveis")
@SeeAlso({})
@ReadsAttributes({
    @ReadsAttribute(attribute = "jwt.*", description = "Atributos opcionais usados como claims no token JWT")
})
@WritesAttributes({@WritesAttribute(attribute="", description="")})
public class TokenGeneratorViasoft extends AbstractProcessor {

    public static final PropertyDescriptor TOKEN_EXPIRATION = new PropertyDescriptor
    .Builder().name("Token Expiration")
    .displayName("Expiração do Token (segundos)")
    .description("Tempo de expiração do token em segundos após a emissão.")
    .required(true)
    .addValidator(StandardValidators.LONG_VALIDATOR)
    .build();

    public static final PropertyDescriptor CONFIG_TYPE_TOKEN = new PropertyDescriptor
    .Builder()
    .name("Token Configure Security")
    .displayName("Chave Privada")
    .description("Chave privada RSA usada para assinar o token JWT no formato PEM ou Base64. Ex: -----BEGIN PRIVATE KEY----- ...")
    .required(true) 
    .sensitive(true)
    .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
    .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
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
        descriptors.add(CONFIG_TYPE_TOKEN);
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
    public void onTrigger(final ProcessContext context, final ProcessSession session) throws ProcessException {
    FlowFile flowFile = session.get();
    if (flowFile == null) {
        return;
    }

    final ComponentLog logger = getLogger();

    try {
        long expirationSecs = context.getProperty(TOKEN_EXPIRATION)
                .evaluateAttributeExpressions(flowFile)
                .asLong();

        ZonedDateTime nowBrasilia = ZonedDateTime.now(ZoneId.of("America/Sao_Paulo"));
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss");

        Date now = new Date();
        Date expiration = new Date(now.getTime() + (expirationSecs * 1000));

        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                .issuer("Token Agent")
                .issueTime(now)
                .expirationTime(expiration)
                .claim(getIdentifier(), expiration);

        Map<String, String> atributosToken = new HashMap<>();

        for (Map.Entry<PropertyDescriptor, String> entry : context.getProperties().entrySet()) {
            PropertyDescriptor descriptor = entry.getKey();
            if (descriptor.isDynamic()) {
                String key = descriptor.getName();
                String value = context.getProperty(descriptor)
                        .evaluateAttributeExpressions(flowFile)
                        .getValue();

                if (value != null) {
                    claimsBuilder.claim(key, value);
                    atributosToken.put("Token." + key, value);
                }
            }
        }

        JWTClaimsSet claims = claimsBuilder.build();

        String privateKeyPEM = context.getProperty(CONFIG_TYPE_TOKEN)
                .evaluateAttributeExpressions(flowFile)
                .getValue();

        String pemClean = privateKeyPEM
        .replace("-----BEGIN PRIVATE KEY-----", "")
        .replace("-----END PRIVATE KEY-----", "")
        .replaceAll("\\s+", ""); 

        byte[] keyBytes = Base64.getDecoder().decode(pemClean);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        if (privateKey instanceof RSAPrivateKey) {
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey;
            int keyLength = rsaPrivateKey.getModulus().bitLength();
            if (keyLength < 2048) {
                throw new ProcessException("Chave RSA muito pequena, precisa ter pelo menos 2048 bits");
            }
        }

        JWSSigner signer = new RSASSASigner(privateKey);

        JWSHeader header = new JWSHeader(JWSAlgorithm.RS256);
        SignedJWT signedJWT = new SignedJWT(header, claims);
        signedJWT.sign(signer);

        String token = signedJWT.serialize();

        atributosToken.put("Token.id", token);
        atributosToken.put("Token.data", nowBrasilia.format(formatter));
        atributosToken.put("Token.exp", expiration.toInstant().toString());

        flowFile = session.putAllAttributes(flowFile, atributosToken);
        session.transfer(flowFile, REL_SUCCESS);

    } catch (Exception e) {
        logger.error("Erro ao gerar token JWT", e);
        flowFile = session.putAttribute(flowFile, "token.error", e.getMessage());
        session.transfer(flowFile, REL_FAILURE);
    }
}

   
}

