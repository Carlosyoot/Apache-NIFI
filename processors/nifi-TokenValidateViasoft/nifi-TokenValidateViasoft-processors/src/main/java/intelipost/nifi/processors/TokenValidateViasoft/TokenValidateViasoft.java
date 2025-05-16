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
package intelipost.nifi.processors.TokenValidateViasoft;

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

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import java.nio.charset.StandardCharsets;
import java.sql.Date;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

@Tags({"example"})
@CapabilityDescription("Provide a description")
@SeeAlso({})
@ReadsAttributes({@ReadsAttribute(attribute="", description="")})
@WritesAttributes({@WritesAttribute(attribute="", description="")})
public class TokenValidateViasoft extends AbstractProcessor {

    public static final PropertyDescriptor ORIGEM = new PropertyDescriptor
        .Builder().name("origem-token")
        .displayName("Origem do Token")
        .description("Define onde o token JWT será lido: cabeçalhos HTTP, parâmetros ou header Authorization padrão.")
        .required(true)
        .allowableValues("Headers", "Params", "Authorization")
        .defaultValue("Authorization")
        .build();

    public static final PropertyDescriptor RETRY_TOKEN = new PropertyDescriptor
        .Builder().name("usar-token")
        .displayName("Revalidar Token")
        .description("Se verdadeiro, e o token estiver expirado. O processador automaticamente irá extender o tempo de expiração")
        .required(true)
        .allowableValues("true", "false")
        .defaultValue("true")
        .build();

    public static final PropertyDescriptor SECRET_KEY = new PropertyDescriptor
        .Builder().name("secret-key")
        .displayName("Chave Secreta")
        .description("Chave secreta usada para validar a assinatura do token JWT. Pode ser fixa ou vinda de um atributo.")
        .required(true)
        .sensitive(true)
        .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
        .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
        .build();

    public static final PropertyDescriptor EXIBIR_CLAIMS = new PropertyDescriptor
        .Builder().name("exibir-claims")
        .displayName("Exibir Claims do Token")
        .description("Se verdadeiro, exibe os dados internos (claims) do token nos atributos do FlowFile.")
        .required(true)
        .allowableValues("true", "false")
        .defaultValue("false")
        .build();
            

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
        descriptors.add(ORIGEM);
        descriptors.add(RETRY_TOKEN);
        descriptors.add(SECRET_KEY);
        descriptors.add(EXIBIR_CLAIMS);
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
        final String origem = context.getProperty(ORIGEM).getValue();
        final boolean retry = context.getProperty(RETRY_TOKEN).asBoolean();
        final boolean exibirClaims = context.getProperty(EXIBIR_CLAIMS).asBoolean();
        final String secretKey = context.getProperty(SECRET_KEY)
                .evaluateAttributeExpressions(flowFile).getValue();

        String token = null;

        // === Extrair token de acordo com a origem ===
        switch (origem) {
            case "Headers":
                token = Optional.ofNullable(flowFile.getAttribute("http.headers.Token"))
                        .orElse(flowFile.getAttribute("http.headers.token"));
                break;

            case "Authorization":
                String authHeader = flowFile.getAttribute("http.headers.Authorization");
                if (authHeader != null && authHeader.toLowerCase().startsWith("bearer ")) {
                    token = authHeader.substring(7).trim(); // remove "Bearer "
                }
                break;

            case "Params":
                token = Optional.ofNullable(flowFile.getAttribute("http.params.token"))
                        .orElse(flowFile.getAttribute("http.params.Token"));
                break;

            default:
                logger.error("Origem do token não reconhecida: " + origem);
                session.transfer(flowFile, REL_FAILURE);
                return;
        }

        if (token == null || token.isEmpty()) {
            logger.warn("Token JWT não encontrado na origem definida: " + origem);
            flowFile = session.putAttribute(flowFile, "jwt.validation", "missing");
            session.transfer(flowFile, REL_FAILURE);
            return;
        }

        // === Validar token JWT ===
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(secretKey.getBytes(StandardCharsets.UTF_8))
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            Instant now = Instant.now();
            Date expiration = (Date) claims.getExpiration();
            boolean isExpired = expiration != null && expiration.toInstant().isBefore(now);

            if (isExpired) {
                if (retry) {
                    // Recria token com nova expiração (ex: +15 minutos)
                    Instant newExp = now.plus(Duration.ofMinutes(15));

                    String renewedToken = Jwts.builder()
                            .setClaims(claims)
                            .setExpiration(Date.from(newExp))
                            .signWith(Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8)))
                            .compact();

                    flowFile = session.putAttribute(flowFile, "jwt.renewed", "true");
                    flowFile = session.putAttribute(flowFile, "jwt.token", renewedToken);
                } else {
                    flowFile = session.putAttribute(flowFile, "jwt.valid", "false");
                    flowFile = session.putAttribute(flowFile, "jwt.error", "Token expirado");
                    session.transfer(flowFile, REL_FAILURE);
                    return;
                }
            } else {
                flowFile = session.putAttribute(flowFile, "jwt.valid", "true");
            }

            // === Exibir claims (Auth.claimName) ===
            if (exibirClaims) {
                for (Map.Entry<String, Object> entry : claims.entrySet()) {
                    String attrName = "Auth." + entry.getKey();
                    String value = String.valueOf(entry.getValue());
                    flowFile = session.putAttribute(flowFile, attrName, value);
                }
            }

            session.transfer(flowFile, REL_SUCCESS);

        } catch (JwtException e) {
            logger.error("Falha ao validar token JWT: {}", new Object[]{e.getMessage()}, e);
            flowFile = session.putAttribute(flowFile, "jwt.valid", "false");
            flowFile = session.putAttribute(flowFile, "jwt.error", e.getMessage());
            session.transfer(flowFile, REL_FAILURE);
        }

    } catch (Exception e) {
        logger.error("Erro inesperado ao processar o token JWT", e);
        flowFile = session.putAttribute(flowFile, "jwt.error", "Erro inesperado: " + e.getMessage());
        session.transfer(flowFile, REL_FAILURE);
    }
}

}
