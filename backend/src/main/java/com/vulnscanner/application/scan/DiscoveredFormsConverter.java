package com.vulnscanner.application.scan;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

import java.util.List;

@Converter
public class DiscoveredFormsConverter implements AttributeConverter<List<DiscoveredForm>, String> {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final TypeReference<List<DiscoveredForm>> FORMS_TYPE = new TypeReference<>() {};

    @Override
    public String convertToDatabaseColumn(List<DiscoveredForm> forms) {
        try {
            return OBJECT_MAPPER.writeValueAsString(forms == null ? List.of() : forms);
        } catch (JsonProcessingException exception) {
            throw new IllegalArgumentException("Unable to serialize discovered forms", exception);
        }
    }

    @Override
    public List<DiscoveredForm> convertToEntityAttribute(String value) {
        if (value == null || value.isBlank()) {
            return List.of();
        }
        try {
            return List.copyOf(OBJECT_MAPPER.readValue(value, FORMS_TYPE));
        } catch (JsonProcessingException exception) {
            throw new IllegalStateException("Unable to deserialize persisted discovered forms", exception);
        }
    }
}
