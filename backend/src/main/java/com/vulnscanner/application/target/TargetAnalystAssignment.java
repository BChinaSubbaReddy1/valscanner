package com.vulnscanner.application.target;

import com.vulnscanner.application.user.User;
import jakarta.persistence.*;

import java.time.Instant;

@Entity
@Table(name = "target_analyst_assignments",
        uniqueConstraints = @UniqueConstraint(
                name = "uk_target_analyst_assignment",
                columnNames = {"target_id", "analyst_user_id"}),
        indexes = @Index(name = "idx_target_assignments_analyst", columnList = "analyst_user_id"))
public class TargetAnalystAssignment {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "target_id", nullable = false)
    private Target target;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "analyst_user_id", nullable = false)
    private User analyst;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "assigned_by_user_id", nullable = false)
    private User assignedBy;

    @Column(name = "assigned_at", nullable = false, updatable = false)
    private Instant assignedAt = Instant.now();

    protected TargetAnalystAssignment() {
    }

    public TargetAnalystAssignment(Target target, User analyst, User assignedBy) {
        this.target = target;
        this.analyst = analyst;
        this.assignedBy = assignedBy;
    }

    public Long getId() {
        return id;
    }

    public Target getTarget() {
        return target;
    }

    public User getAnalyst() {
        return analyst;
    }

    public User getAssignedBy() {
        return assignedBy;
    }

    public Instant getAssignedAt() {
        return assignedAt;
    }
}
