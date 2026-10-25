package com.vulnscanner.application;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulnscanner.application.audit.AuditEventRepository;
import com.vulnscanner.application.organization.Organization;
import com.vulnscanner.application.organization.OrganizationRepository;
import com.vulnscanner.application.organization.OrganizationStatus;
import com.vulnscanner.application.role.Role;
import com.vulnscanner.application.role.RoleName;
import com.vulnscanner.application.role.RoleRepository;
import com.vulnscanner.application.target.Target;
import com.vulnscanner.application.target.TargetRepository;
import com.vulnscanner.application.target.TargetStatus;
import com.vulnscanner.application.user.User;
import com.vulnscanner.application.user.UserRepository;
import com.vulnscanner.application.user.UserStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class TargetManagementIntegrationTest {
    private static final String PASSWORD = "SecurePassword123!";

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private UserRepository userRepository;
    @Autowired private RoleRepository roleRepository;
    @Autowired private OrganizationRepository organizationRepository;
    @Autowired private TargetRepository targetRepository;
    @Autowired private AuditEventRepository auditEventRepository;
    @Autowired private PasswordEncoder passwordEncoder;

    @BeforeEach
    void initializeRoles() {
        for (RoleName name : new RoleName[]{
                RoleName.SUPER_ADMIN, RoleName.ADMIN, RoleName.SECURITY_ANALYST}) {
            roleRepository.findByName(name).orElseGet(() -> roleRepository.save(new Role(name)));
        }
    }

    @Test
    void adminCreatesApprovesAndSoftDeletesTargetWithAuditHistory() throws Exception {
        Organization organization = approvedOrganization("Target Tenant");
        User admin = createUser(RoleName.ADMIN, "target-admin@example.com", organization);
        String token = login(admin.getEmail());

        String createdBody = mockMvc.perform(post("/api/targets")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"name":"Public app","url":"https://example.org/app","type":"WEB_APPLICATION",
                                 "organizationId":9999}
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.data.status").value("PENDING"))
                .andExpect(jsonPath("$.data.organizationId").value(organization.getId()))
                .andReturn().getResponse().getContentAsString();

        JsonNode createdJson = objectMapper.readTree(createdBody);
        long targetId = createdJson.path("data").path("id").asLong();
        assertEquals(1, targetRepository.count());
        assertEquals(1, auditEventRepository.count());

        mockMvc.perform(post("/api/targets/{id}/decision", targetId)
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"decision\":\"APPROVE\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.status").value("APPROVED"));

        mockMvc.perform(delete("/api/targets/{id}", targetId)
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.status").value("DELETED"));

        Target target = targetRepository.findById(targetId).orElseThrow();
        assertEquals(TargetStatus.DELETED, target.getStatus());
        assertEquals(3, auditEventRepository.count());
        assertTrue(auditEventRepository.findAll().stream()
                .anyMatch(event -> "TARGET_DELETED".equals(event.getEventType())
                        && event.getOrganization().getId().equals(organization.getId())));
    }

    @Test
    void analystsSeeOnlyApprovedTargetsInTheirOwnOrganization() throws Exception {
        Organization organization = approvedOrganization("Analyst Tenant");
        Organization otherOrganization = approvedOrganization("Other Target Tenant");
        User admin = createUser(RoleName.ADMIN, "analyst-target-admin@example.com", organization);
        User analyst = createUser(RoleName.SECURITY_ANALYST, "target-analyst@example.com", organization);
        User otherAdmin = createUser(RoleName.ADMIN, "other-target-admin@example.com", otherOrganization);
        createUser(RoleName.SECURITY_ANALYST, "other-target-analyst@example.com", otherOrganization);
        Target pending = createTarget(organization, admin, "Pending target", TargetStatus.PENDING);
        Target approved = createTarget(organization, admin, "Approved target", TargetStatus.APPROVED);
        createTarget(otherOrganization, otherAdmin, "Foreign target", TargetStatus.APPROVED);

        String analystToken = login(analyst.getEmail());
        mockMvc.perform(get("/api/targets").header("Authorization", "Bearer " + analystToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.length()").value(1))
                .andExpect(jsonPath("$.data[0].id").value(approved.getId()))
                .andExpect(jsonPath("$.data[0].id").value(org.hamcrest.Matchers.not(pending.getId())));

        mockMvc.perform(get("/api/targets/{id}", approved.getId())
                        .header("Authorization", "Bearer " + analystToken))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/targets/{id}", pending.getId())
                        .header("Authorization", "Bearer " + analystToken))
                .andExpect(status().isNotFound());

        mockMvc.perform(post("/api/targets")
                        .header("Authorization", "Bearer " + login(analyst.getEmail()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(targetRequest("Analyst target", "https://example.org")))
                .andExpect(status().isForbidden());
    }

    @Test
    void targetIdsCannotBeUsedAcrossOrganizationsAndInvalidUrlCannotBeCreated() throws Exception {
        Organization firstOrganization = approvedOrganization("First Target Tenant");
        Organization secondOrganization = approvedOrganization("Second Target Tenant");
        User firstAdmin = createUser(RoleName.ADMIN, "first-target-admin@example.com", firstOrganization);
        User secondAdmin = createUser(RoleName.ADMIN, "second-target-admin@example.com", secondOrganization);
        Target target = createTarget(firstOrganization, firstAdmin, "Private target", TargetStatus.PENDING);
        String secondToken = login(secondAdmin.getEmail());

        mockMvc.perform(get("/api/targets/{id}", target.getId())
                        .header("Authorization", "Bearer " + secondToken))
                .andExpect(status().isNotFound());
        mockMvc.perform(post("/api/targets/{id}/decision", target.getId())
                        .header("Authorization", "Bearer " + secondToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"decision\":\"APPROVE\"}"))
                .andExpect(status().isNotFound());
        mockMvc.perform(delete("/api/targets/{id}", target.getId())
                        .header("Authorization", "Bearer " + secondToken))
                .andExpect(status().isNotFound());

        mockMvc.perform(post("/api/targets")
                        .header("Authorization", "Bearer " + secondToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(targetRequest("Bad URL", "javascript:alert(1)")))
                .andExpect(status().isBadRequest());
        assertEquals(TargetStatus.PENDING, targetRepository.findById(target.getId()).orElseThrow().getStatus());
    }

    @Test
    void adminCanRegisterUnlistedPublicHttpAndHttpsTargetsButNotInvalidPorts() throws Exception {
        Organization organization = approvedOrganization("Dynamic Public Targets");
        User admin = createUser(RoleName.ADMIN, "dynamic-public-target-admin@example.com", organization);
        String token = login(admin.getEmail());

        for (String url : Set.of("http://unlisted-http.public.example/app",
                "https://unlisted-https.public.example/app")) {
            mockMvc.perform(post("/api/targets")
                            .header("Authorization", "Bearer " + token)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(targetRequest("Unlisted public site", url)))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.data.url").value(url))
                    .andExpect(jsonPath("$.data.status").value("PENDING"));
        }

        mockMvc.perform(post("/api/targets")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(targetRequest("Bad port", "https://bad-port.public.example:70000/")))
                .andExpect(status().isBadRequest());
        mockMvc.perform(post("/api/targets")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(targetRequest("Empty port", "https://empty-port.public.example:/")))
                .andExpect(status().isBadRequest());
    }

    private Organization approvedOrganization(String name) {
        Organization organization = new Organization();
        organization.setName(name);
        organization.setContactEmail("ops@example.com");
        organization.setPrimaryContactName("Operations");
        organization.setStatus(OrganizationStatus.APPROVED);
        return organizationRepository.save(organization);
    }

    private User createUser(RoleName roleName, String email, Organization organization) {
        User user = new User();
        user.setFirstName("Test");
        user.setLastName("User");
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(PASSWORD));
        user.setStatus(UserStatus.ACTIVE);
        user.setOrganization(organization);
        user.setRoles(Set.of(roleRepository.findByName(roleName).orElseThrow()));
        return userRepository.save(user);
    }

    private Target createTarget(Organization organization, User creator, String name, TargetStatus status) {
        Target target = new Target();
        target.setName(name);
        target.setUrl("https://example.org/" + name.toLowerCase().replace(' ', '-'));
        target.setType(com.vulnscanner.application.target.TargetType.WEB_APPLICATION);
        target.setOrganization(organization);
        target.setCreatedBy(creator);
        target.setStatus(status);
        return targetRepository.save(target);
    }

    private String targetRequest(String name, String url) throws Exception {
        return objectMapper.writeValueAsString(java.util.Map.of(
                "name", name, "url", url, "type", "WEB_APPLICATION"));
    }

    private String login(String email) throws Exception {
        String response = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"" + PASSWORD + "\"}"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return objectMapper.readTree(response).path("data").path("token").asText();
    }
}
