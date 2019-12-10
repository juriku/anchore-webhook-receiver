# Anchore Engine webhook receiver server nd slack notification sender

## From [Anchore Engine](https://github.com/anchore/anchore-engine)

- Container will recieve webhooks from "analysis_update" (only this one works properly now), whioch will include image that just got scanned by Anchore
- Service will extract image and query Anchore API for imageId
- With imageId service will query Anchore API for all vulnerabilities
- list of vulnerabilities will be filtered for High and Critical Only (with versions and fix)
- This list will be formatted for Slack and passed slack webhoo if one is provided

## variables to pass to docker container
- PORT         = listening port (default 8440)
- HOST         = host to listen from (default '0.0.0.0')
- ANCHORE_USER = anchore user (default 'admin') have to be the same as used for image analysis
- ANCHORE_PASS = anchore user password (default 'foobar')
- ANCHORE_HOST = anchore API host (default 'localhost')
- ANCHORE_PORT = anchore API port (default 8228)
- SLACK_URL    = slack webhook url (no default)
