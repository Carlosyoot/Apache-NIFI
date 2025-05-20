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
package intelipost.nifi.processors.sqlprocessor;



import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.dbcp.DBCPService;
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

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;


@Tags({"sql","consult","boolean","viasoft"})
@CapabilityDescription("Executa uma consulta SQL validando o retorno da query, retornando um atributo booleano e outro com o resultado")
@SeeAlso({})
@ReadsAttributes({@ReadsAttribute(attribute="", description="")})
@WritesAttributes({
    @WritesAttribute(attribute = "sql.result", description = "Resultado da consulta SQL como string, apenas os valores."),
    @WritesAttribute(attribute = "sql.valid", description = "Booleano indicando se a consulta retornou dados.")
})
public class SqlProcessorViasoft extends AbstractProcessor {


    public static final PropertyDescriptor SQL_QUERY = new PropertyDescriptor
    .Builder().name("SQL")
    .displayName("Consulta SQL")
    .description("A consulta SQL que será executada no banco de dados Oracle")
    .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
    .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
    .required(true)
    .build();


    public static final PropertyDescriptor DBCP_SERVICE = new PropertyDescriptor
        .Builder().name("Conexão de banco")
        .displayName("Conexão Remota")
        .description("O serviço do controlador que fornece conexões de banco de dados.")
        .identifiesControllerService(DBCPService.class)
        .required(true)
        .build();


    public static final Relationship REL_SUCCESS  = new Relationship.Builder()
        .description("Sucesso no processo")
        .name("Sucesso")
        .build();

    public static final Relationship REL_FAILURE = new Relationship.Builder()
        .description("Falha no processo")
        .name("Falha")
        .build();

    private List<PropertyDescriptor> descriptors;

    private Set<Relationship> relationships;

    @Override
    protected void init(final ProcessorInitializationContext context) {
    final List<PropertyDescriptor> descriptors = new ArrayList<>();
    descriptors.add(DBCP_SERVICE);
    descriptors.add(SQL_QUERY);
    this.descriptors = Collections.unmodifiableList(descriptors);

    final Set<Relationship> relationships = new HashSet<>();
    relationships.add(REL_SUCCESS);
    relationships.add(REL_FAILURE);
    this.relationships = Collections.unmodifiableSet(relationships);
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

    final String sql = context.getProperty(SQL_QUERY)
            .evaluateAttributeExpressions(flowFile)
            .getValue();

    final DBCPService dbcpService = context.getProperty(DBCP_SERVICE)
            .asControllerService(DBCPService.class);

    try (final Connection conn = dbcpService.getConnection();
         final PreparedStatement stmt = conn.prepareStatement(sql);
         final ResultSet rs = stmt.executeQuery()) {

        final ResultSetMetaData meta = rs.getMetaData();
        final int columnCount = meta.getColumnCount();

        final Map<String, String> attributes = new HashMap<>();
        boolean allValid = true;

        if (rs.next()) {
            for (int i = 1; i <= columnCount; i++) {
                String alias = meta.getColumnLabel(i);
                String value = rs.getString(i);
                if (value == null) value = "";

                String attrName = alias.toLowerCase();
                boolean isValid = !value.isEmpty();

                attributes.put(attrName + ".result", value);
                attributes.put(attrName + ".valid", String.valueOf(isValid));

                if (!isValid) {
                    allValid = false;
                }
            }
        } else {

            for (int i = 1; i <= columnCount; i++) {
                String alias = meta.getColumnLabel(i);
                String attrName = alias.toLowerCase();

                attributes.put(attrName + ".result", "");
                attributes.put(attrName + ".valid", "false");

                allValid = false; 
            }
        }

        attributes.put("sql.valid", String.valueOf(allValid));

        flowFile = session.putAllAttributes(flowFile, attributes);
        session.transfer(flowFile, REL_SUCCESS);

    } catch (Exception e) {
        getLogger().error("Erro ao executar SQL: {}", new Object[]{e.getMessage()}, e);
        session.transfer(flowFile, REL_FAILURE);
    }
    }

}
