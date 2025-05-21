package intelipost.nifi.processors.SecretManager;

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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@Tags({"security","token","provider","auth","secret","jwt"})
@CapabilityDescription(
    "Gera chaves secretas para validação de segurança, ou cria arquivos PEM (chaves públicas e privadas) " +
    "para assinar tokens JWT. Existem dois tipos de chave: \n\n" +
    
    "1. **Cliente**: Gera uma chave secreta aleatória (UUID) usada para validação de rotas, senhas e outros " +
    "processos de segurança específicos da aplicação. \n\n" +
    
    "2. **Aplicação**: Gera um par de chaves RSA (públicas e privadas), que são utilizadas para assinar e verificar " +
    "tokens JWT. Esses pares de chaves são armazenados de forma segura e encriptada. \n\n" +
    
    "O processador pode forçar a criação de uma nova chave a cada execução com a configuração 'Forçar Nova Chave'. " +
    "Se definida como **true**, uma nova chave será gerada, invalidando as anteriores. Caso contrário, a mesma chave " +
    "será retornada por padrão, garantindo consistência ao longo do tempo.\n\n" +
    
    "As chaves públicas e privadas devem ser conhecidas apenas pela aplicação, garantindo a segurança dos dados " +
    "e da comunicação.")
@ReadsAttributes({@ReadsAttribute(attribute="", description="")})
@WritesAttributes({@WritesAttribute(attribute="secret.key", description="A chave secreta gerada e persistida para assinatura de JWTs")})
public class SecretManager extends AbstractProcessor {

    public static final PropertyDescriptor KEY_TYPE = new PropertyDescriptor
        .Builder().name("key-type")
        .displayName("Tipo de Chave")
        .description("Define se o processador vai gerar/recuperar chave para CLIENTE (string aleatória) ou APLICAÇÃO (par RSA).")
        .required(true)
        .allowableValues("Cliente", "Aplicação")
        .defaultValue("Cliente")
        .build();

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
        descriptors.add(KEY_TYPE);
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

    final ComponentLog logger = getLogger();
    final StateManager stateManager = context.getStateManager();

    try {
        StateMap stateMap = stateManager.getState(Scope.LOCAL);

        boolean forceNew = context.getProperty(FORCE_NEW_SECRET).asBoolean();
        String keyType = context.getProperty(KEY_TYPE).getValue();

        if ("Cliente".equalsIgnoreCase(keyType)) {
            String clientKey = stateMap.get("client.key");

            if (clientKey == null || forceNew) {
                clientKey = UUID.randomUUID().toString() + UUID.randomUUID().toString();
                Map<String, String> newState = new HashMap<>();
                newState.put("client.key", clientKey);
                stateManager.setState(newState, Scope.LOCAL);
                logger.info("Nova chave CLIENTE gerada e armazenada.");
            } else {
                logger.info("Chave CLIENTE recuperada do estado.");
            }

            
            flowFile = session.putAttribute(flowFile, "client.key", clientKey);
    

        } else if ("APLICAÇÃO".equalsIgnoreCase(keyType)) {
            String privateKeyPEM = stateMap.get("app.private.key");
            String publicKeyPEM = stateMap.get("app.public.key");

            if (privateKeyPEM == null || publicKeyPEM == null || forceNew) {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(2048);
                KeyPair keyPair = keyGen.generateKeyPair();

                privateKeyPEM = pemFormat(keyPair.getPrivate().getEncoded(), "PRIVATE KEY");
                publicKeyPEM = pemFormat(keyPair.getPublic().getEncoded(), "PUBLIC KEY");

                Map<String, String> newState = new HashMap<>();
                newState.put("app.private.key", privateKeyPEM);
                newState.put("app.public.key", publicKeyPEM);
                stateManager.setState(newState, Scope.LOCAL);

                logger.info("Novas chaves RSA geradas e armazenadas.");
            } else {
                logger.info("Chaves RSA recuperadas do estado.");
            }
                flowFile = session.putAttribute(flowFile, "app.private.key", privateKeyPEM);
                flowFile = session.putAttribute(flowFile, "app.public.key", publicKeyPEM);
            

        } else {
            logger.error("Tipo de chave desconhecido: " + keyType);
            session.transfer(flowFile, REL_FAILURE);
            return;
        }

        session.transfer(flowFile, REL_SUCCESS);

    } catch (Exception e) {
        logger.error("Erro ao gerar ou recuperar chave", e);
        session.transfer(flowFile, REL_FAILURE);
        }
    }

    private String pemFormat(byte[] keyBytes, String keyType) {
        String base64Encoded = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(keyBytes);
        return "-----BEGIN " + keyType + "-----\n" + base64Encoded + "\n-----END " + keyType + "-----";
    }

}