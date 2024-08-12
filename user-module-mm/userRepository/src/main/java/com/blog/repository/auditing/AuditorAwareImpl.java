package com.blog.repository.auditing;

import org.springframework.data.domain.AuditorAware;
import org.springframework.stereotype.Component;

import java.util.Optional;

//* Implementation of the AuditorAware interface to provide current auditor information.
//* This is used to automatically populate auditing fields like 'createdBy' and 'lastModifiedBy'.
@Component
public class AuditorAwareImpl implements AuditorAware<String> {
    // *ThreadLocal to store the current auditor for each thread.
    private static final ThreadLocal<String> currentAuditor = new ThreadLocal<>();

    //* Retrieves the current auditor from the ThreadLocal.
    //* This method is used by Spring Data JPA to get the value of the 'createdBy' and 'lastModifiedBy' fields.
    //* @return an Optional containing the current auditor, or an empty Optional if no auditor is set.
    @Override
    public Optional<String> getCurrentAuditor() {
        return Optional.ofNullable(currentAuditor.get());
    }

   // * Sets the current auditor in the ThreadLocal.
   // *This method is typically called at the start of a request to set the auditor for the current thread.
   // * @param auditor the identifier of the current auditor (e.g., username or user ID).
    public static void setCurrentAuditor(String auditor) {
        currentAuditor.set(auditor);
    }

    //* Clears the current auditor from the ThreadLocal.
    //* This method is called to remove the auditor information after the request is processed.
    public static void clear() {
        currentAuditor.remove();
    }
}