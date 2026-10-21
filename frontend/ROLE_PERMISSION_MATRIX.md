# Role permission matrix

| Role | Organization registry | Organization users | Targets | Analyst workspace | Scans / findings / reports |
| --- | ---: | ---: | ---: | ---: | ---: |
| `SUPER_ADMIN` | Review requests, registry metadata, approve/reject, guarded deactivation | No tenant user access | No | No | No |
| `ADMIN` (Organization Admin) | No | Own organization only: analyst approvals and account lifecycle actions | Own organization only | No | No |
| `SECURITY_ANALYST` | No | No | Read approved targets only through backend | Yes | Own organization-authorized scans and persisted findings through scan endpoints |

Public registration offers only `ADMIN` (Organization Admin) and `SECURITY_ANALYST`. The registration form submits organization names, not organization IDs or invitation tokens. Backend authorization remains authoritative; frontend route guards only improve usability.

The Super Admin registry contains organization metadata only. It does not grant access to any organization's targets, scans, users, findings, or reports. Organization Admin user-management calls use `/api/organizations/me/...` endpoints and do not accept a client-selected organization ID.
