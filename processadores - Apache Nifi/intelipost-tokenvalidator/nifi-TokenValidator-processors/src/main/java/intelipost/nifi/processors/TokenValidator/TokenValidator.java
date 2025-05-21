package intelipost.nifi.processors.TokenValidator;

import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.components.PropertyValue;
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
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import io.jsonwebtoken.SignatureAlgorithm;
import java.sql.Date;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

@Tags({"security","token","provider","auth"})
@CapabilityDescription(
    "Valida tokens JWT assinados com algoritmo RS256, utilizando a chave pública RSA gerada pelo SecretManager. "
  + "O token é analisado quanto à sua integridade, validade temporal (expiração) e assinatura digital.\n\n"
  + "Tokens assinados com chaves privadas diferentes da vinculada à chave pública configurada serão rejeitados.\n\n"
  + "Caso a validação falhe, atributos informativos são adicionados ao FlowFile explicando o motivo, como expiração ou falha de assinatura.\n\n"
  + "Se a opção de revalidação estiver ativada (Revalidar Token = true) e o token estiver expirado, o processador poderá gerar "
  + "um novo token com novo tempo de expiração, desde que a chave privada RSA correspondente esteja fornecida nas propriedades.\n\n"
  + "Permite configurar a origem do token: cabeçalhos HTTP personalizados, parâmetro Authorization padrão, parâmetros de URL ou atributos do FlowFile.\n\n"
  + "Opcionalmente, pode-se exibir os dados internos (claims) do token como atributos do FlowFile para uso posterior no fluxo."
)@SeeAlso({})
@ReadsAttributes({@ReadsAttribute(attribute="", description="")})
@WritesAttributes({@WritesAttribute(attribute="", description="")})
public class TokenValidator extends AbstractProcessor {

    public static final PropertyDescriptor ORIGEM = new PropertyDescriptor
    .Builder().name("origem-token")
    .displayName("Origem do Token")
    .description("Define onde o token JWT será lido: cabeçalhos HTTP, parâmetros, atributos ou header Authorization padrão.")
    .required(true)
    .allowableValues("Headers", "Params", "Authorization","Attributes")
    .defaultValue("Authorization")
    .build();

    public static final PropertyDescriptor PARAM = new PropertyDescriptor
        .Builder()
        .name("attribute-token")
        .displayName("Expressão Param")
        .description("Campo para obter o token através do atributo de um FlowFile. Suporta Expression Language.")
        .required(false)
        .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
        .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
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

    public static final PropertyDescriptor PUBLIC_KEY = new PropertyDescriptor
        .Builder()
        .name("RSA Public Key")
        .displayName("Chave Pública RSA")
        .description("Chave pública RSA para validar o token JWT. Deve ser a chave pública correspondente à chave privada usada para assinar.")
        .required(true)
        .sensitive(true)
        .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
        .expressionLanguageSupported(ExpressionLanguageScope.NONE)
        .build();

    public static final PropertyDescriptor PRIVATE_KEY = new PropertyDescriptor
        .Builder()
        .name("RSA Private Key")
        .displayName("Chave Privada RSA")
        .description("Chave privada RSA usada para renovar o token JWT. Necessária apenas se a opção de renovação estiver ativada.")
        .required(false)
        .sensitive(true)
        .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
        .expressionLanguageSupported(ExpressionLanguageScope.NONE)
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
        .description("Sucesso na validação do token JWT.")
        .name("Sucesso")
        .build();

    public static final Relationship REL_FAILURE = new Relationship.Builder()
        .description("Falha na validação do token JWT.")
        .name("Falha")
        .build();

    private List<PropertyDescriptor> descriptors;

    private Set<Relationship> relationships;

    @Override
    protected void init(final ProcessorInitializationContext context) {
        descriptors = new ArrayList<>();
        descriptors.add(ORIGEM);
        descriptors.add(PARAM);
        descriptors.add(RETRY_TOKEN);
        descriptors.add(PUBLIC_KEY);
        descriptors.add(PRIVATE_KEY);
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
        final String publicKeyPem = context.getProperty(PUBLIC_KEY).evaluateAttributeExpressions(flowFile).getValue();

        PublicKey publicKey = getPublicKeyFromPem(publicKeyPem);

        String token = null;

        switch (origem) {
            case "Headers":
                token = flowFile.getAttribute("http.headers.Token");
                if (token == null) token = flowFile.getAttribute("http.headers.token");
                break;

            case "Authorization":
                String authHeader = flowFile.getAttribute("http.headers.Authorization");
                if (authHeader != null && authHeader.toLowerCase().startsWith("bearer ")) {
                    token = authHeader.substring(7).trim();
                }
                break;

            case "Params":
                token = flowFile.getAttribute("http.params.token");
                if (token == null) token = flowFile.getAttribute("http.params.Token");
                break;

            case "Attributes":
                final PropertyValue paramProp = context.getProperty(PARAM);
                final String resolvedValue = paramProp.evaluateAttributeExpressions(flowFile).getValue();
                if (resolvedValue == null || resolvedValue.trim().isEmpty()) {
                    logger.error("A propriedade 'attribute-token' está vazia ou não resolvida.");
                    session.transfer(flowFile, REL_FAILURE);
                } else {
                    token = resolvedValue;
                }
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

        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(publicKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            flowFile = session.putAttribute(flowFile, "jwt.valido", "true");

            if (exibirClaims) {
                flowFile = aplicarClaimsPersonalizados(session, flowFile, claims);
            }
        
            session.transfer(flowFile, REL_SUCCESS);
        
        } catch (ExpiredJwtException e) {
            Claims claims = e.getClaims();
        
            if (retry) {
                final String privateKeyPem = context.getProperty(PRIVATE_KEY).evaluateAttributeExpressions(flowFile).getValue();
            
                if (privateKeyPem == null || privateKeyPem.trim().isEmpty()) {
                    logger.error("Renovação ativada, mas chave privada RSA não foi fornecida.");
                    flowFile = session.putAttribute(flowFile, "jwt.valido", "false");
                    flowFile = session.putAttribute(flowFile, "jwt.error", "Renovação ativada, mas chave privada RSA não foi fornecida.");
                    session.transfer(flowFile, REL_FAILURE);
                    return;
                }
            
                PrivateKey privateKey = getPrivateKeyFromPem(privateKeyPem);
            
                Instant now = Instant.now();
                Instant newExp = now.plus(Duration.ofMinutes(15));
                String renewedToken = Jwts.builder()
                        .setClaims(claims)
                        .setExpiration(Date.from(newExp))
                        .signWith(privateKey, SignatureAlgorithm.RS256)
                        .compact();
            
                flowFile = session.putAttribute(flowFile, "jwt.revalidado", "true");
                flowFile = session.putAttribute(flowFile, "jwt.novo.token", renewedToken);

                if (exibirClaims) {
                    flowFile = aplicarClaimsPersonalizados(session, flowFile, claims);
                }

                session.transfer(flowFile, REL_SUCCESS);

                return;
            } else {
                flowFile = session.putAttribute(flowFile, "jwt.valido", "false");
                flowFile = session.putAttribute(flowFile, "jwt.error", "Token expirado");
                session.transfer(flowFile, REL_FAILURE);
                return;
            }

        } catch (JwtException e) {
            logger.error("Falha ao validar token JWT: {}", new Object[]{e.getMessage()}, e);
            flowFile = session.putAttribute(flowFile, "jwt.valido", "false");
            flowFile = session.putAttribute(flowFile, "jwt.error", e.getMessage());
            session.transfer(flowFile, REL_FAILURE);
        }

    } catch (Exception e) {
        logger.error("Erro inesperado ao processar o token JWT", e);
        flowFile = session.putAttribute(flowFile, "jwt.error", "Erro inesperado: " + e.getMessage());
        session.transfer(flowFile, REL_FAILURE);}
    }

    private PublicKey getPublicKeyFromPem(String pem) throws Exception {
    String publicKeyPEM = pem
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replaceAll("\\s+", "");

    byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    return keyFactory.generatePublic(keySpec);
    }   

    private PrivateKey getPrivateKeyFromPem(String pem) throws Exception {
        String privateKeyPEM = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    private static FlowFile aplicarClaimsPersonalizados(ProcessSession session, FlowFile flowFile, Claims claims) {
    DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss");
    ZoneId zone = ZoneId.of("America/Sao_Paulo");

    Map<String, String> traducoes = new HashMap<>();
    traducoes.put("iss", "agente");
    traducoes.put("exp", "expiration");
    traducoes.put("iat", "criado");

    Pattern uuidPattern = Pattern.compile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");

    for (Map.Entry<String, Object> entry : claims.entrySet()) {
        String key = entry.getKey();

        if (uuidPattern.matcher(key).matches()) {
            continue;
        }

        String nomeAtributo = "Auth." + traducoes.getOrDefault(key, key);
        Object valor = entry.getValue();

        if (valor instanceof Number && (key.equals("exp") || key.equals("iat"))) {
            long epoch = ((Number) valor).longValue();
            Instant instante = Instant.ofEpochSecond(epoch);
            String formatado = instante.atZone(zone).format(formatter);
            flowFile = session.putAttribute(flowFile, nomeAtributo, formatado);
        } else {
            flowFile = session.putAttribute(flowFile, nomeAtributo, String.valueOf(valor));
        }
    }
    return flowFile;
    }

}