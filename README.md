# Karton CAPA
> [Karton](https://github.com/CERT-Polska/karton) service for [CAPA](https://github.com/mandiant/capa)

## Prerequisites

This is to be used as part of a [Karton](https://github.com/CERT-Polska/karton) pipeline. It has been setup as a [Docker](https://www.docker.com/) container.

Recommended **docker compose** setup:

```yml
karton-capa:
  build:
    context: karton/capa
  tty: true
  develop:
    watch:
      - action: sync+restart
        path: karton/capa
        target: /app
        ignore:
          - karton/capa/.venv/
      - action: rebuild
        path: karton/capa/uv.lock
      - action: rebuild
        path: karton/capa/Dockerfile
  depends_on:
    - karton-system
    - mwdb-web
  volumes:
    - ./karton.docker.ini:/etc/karton/karton.ini
```

## Behavior

For a given sample, run **CAPA** on it and:
1. Add the detected *TTPs* to the sample as **tags**
2. Extract specific fields from the response and add them to the sample as **attributes**


**Consumes:**
```json
{"type": "sample", "stage": "recognized"}
```

**Produces:**
```json
{
  "headers": {"type": "sample", "stage": "analyzed"},
  "payload": {
    "sample": sample,
    "tags": <Mitre TTP tags>,
    "attributes": {
      "capa": <Minimized CAPA result>
    }
  }
}
```

## Attributes

**Key.** `capa`

**Label.** CAPA result

**Description.** Minified result of running CAPA on the sample
```jinja
<!-- Rich Template -->

{{#value}}
**{{name}}**{{#description}}({{.}}){{/description}}:
{{#attack}}
- {{tactic}}: {{technique}} ({{id}})
{{/attack}}
{{#mbc}}
- {{objective}}: {{behavior}}{{#method}}.{{.}}{{/method}} ({{id}})
{{/mbc}}
{{/value}}
```