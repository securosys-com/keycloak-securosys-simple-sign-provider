
package com.securosys.simple.sign.client.util;

import com.securosys.simple.sign.client.enums.SANType;
import com.securosys.simple.sign.client.jce.exception.BusinessException;
import com.securosys.simple.sign.client.jce.exception.BusinessReason;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
/**
 * Utility class for SubjectAlternativeName.
 */
public class SubjectAlternativeName {

    private SANType sanType;

    private String sanValue;

    /**
     * Factory method that parses a string like "dns:localhost" into a SubjectAlternativeName object.
     * This method is designed to be used with a Stream's map function.
     *
     * @param sanTypeAndValue A single string containing both the SAN type and value, separated by a colon.
     * @return A new SubjectAlternativeName object.
     * @throws BusinessException if the string format is invalid or the type is not recognized.
     */
    public static SubjectAlternativeName fromSubjectAlternativeNamesString(String sanTypeAndValue, String splitCharacter) {
        // 1. Split the input string into two parts at the first colon.
        String[] parts = sanTypeAndValue.split(splitCharacter, 2);
        if (parts.length != 2) {
            String msg = String.format("Invalid SAN format for '%s'. Expected format 'type:value'.", sanTypeAndValue);
            throw new BusinessException(msg, BusinessReason.ERROR_INVALID_VALUE_FOR_ENUM);
        }

        String sanTypeString = parts[0].trim();
        String sanValue = parts[1].trim();

        // 2. Find the corresponding SANType enum from the extracted type string.
        for (SANType type : SANType.values()) {
            if (type.getSanType().equalsIgnoreCase(sanTypeString)) {
                // 3. Return a new object upon finding a match.
                return new SubjectAlternativeName(type, sanValue);
            }
        }

        // 4. If no match is found after checking all enum values, throw an exception.
        String msg = String.format("SubjectAlternativeName type '%s' cannot be mapped to a valid SANType.", sanTypeString);
        throw new BusinessException(msg, BusinessReason.ERROR_INVALID_VALUE_FOR_ENUM);
    }

    @Override
    public String toString() {
        return "SubjectAlternativeName{" +
                "sanType=" + sanType +
                ", sanValue='" + sanValue + '\'' +
                '}';
    }
}
