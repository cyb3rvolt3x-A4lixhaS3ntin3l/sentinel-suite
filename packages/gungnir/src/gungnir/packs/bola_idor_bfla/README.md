# Pack `bola_idor_bfla` (Phase C slice3 / v0)

Defensive hunt pack: **BOLA / horizontal IDOR / vertical BFLA / sibling-method** **candidates + evidence stubs**. Dual-role lab fixtures required. Lab / authorized bounty use only.

## Can

- Require **Role A and Role B** session fixtures (`roles/a.json` + `roles/b.json` or `--role-a` / `--role-b`); **fail closed** with coach-style message if missing
- Emit **horizontal IDOR** candidates when fixtures show Role A reading Role B's object (responses differ / B's object readable with A's session)
- Emit **vertical / BFLA** candidates when fixtures show Role A succeeding on an admin-ish path that Role B/admin can access
- Emit **sibling method** candidates when fixtures show a mutating method (DELETE/PUT/PATCH) allowed where GET is the expected safe method
- Attach finding-gate checklist: `in_scope`, `reproducible`, `impact`, `evidence_attached`
- Honest verification: `confirmed` when fixture baselines/`expect` prove the pattern; otherwise `unverified`
- Evidence request/response stubs **from fixtures only**
- Thin report via `sentinel hunt report <program> --pack bola_idor_bfla`

## Cannot

- Live multi-tenant abuse or cross-customer probing
- Data destruction / destructive PoCs / lockout loops
- Full business-logic assistant or race packs
- nuclei-all, Guard SDK, workflows, X
- Invent Steps without evidence on the graph

## Roles

```json
{"cookies": {"session": "lab-a"}, "headers": {}, "bearer": null}
```

Place at `~/.sentinel/programs/<id>/roles/a.json` and `roles/b.json`.

## Fixtures (lab / tests)

```json
{
  "horizontal_idor": [
    {
      "url": "https://lab.example/api/objects/obj-b",
      "object_id_a": "obj-a",
      "object_id_b": "obj-b",
      "role_a_on_b": {"method": "GET", "status": 200, "body": "{\"owner\":\"b\",\"secret\":\"b-data\"}"},
      "role_b_on_b": {"method": "GET", "status": 200, "body": "{\"owner\":\"b\",\"secret\":\"b-data\"}"},
      "role_a_on_a": {"method": "GET", "status": 200, "body": "{\"owner\":\"a\",\"secret\":\"a-data\"}"},
      "expect": {"idor": true}
    }
  ],
  "vertical_bfla": [
    {
      "url": "https://lab.example/admin/users",
      "role_a": {"method": "GET", "status": 200, "body": "[{\"id\":1}]"},
      "role_b_admin": {"method": "GET", "status": 200, "body": "[{\"id\":1}]"},
      "expect": {"bfla": true}
    }
  ],
  "sibling_methods": [
    {
      "url": "https://lab.example/api/objects/1",
      "get_response": {"status": 200, "body": "{\"id\":1}"},
      "probe_method": "DELETE",
      "probe_response": {"status": 200, "body": "deleted"},
      "expected_deny_statuses": [401, 403, 405],
      "expect": {"method_confusion": true}
    }
  ]
}
```

MIT. `ENGINE_ALLOWLIST` stays `{}`. Scope hard kill; `--scope` or `--i-own-this`.
