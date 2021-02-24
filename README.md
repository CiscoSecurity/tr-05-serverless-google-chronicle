[![Gitter Chat](https://img.shields.io/badge/gitter-join%20chat-brightgreen.svg)](https://gitter.im/CiscoSecurity/Threat-Response "Gitter Chat")

# Google Chronicle Relay (Cisco Hosted)

A Cisco SecureX Concrete Relay implementation using
[Google Chronicle](https://go.chronicle.security/whitepaper-chronicle)
as a third-party Cyber Threat Intelligence service provider.


The Relay itself is just a simple application written in Python that can be easily packaged and deployed.  This relay is now Cisco Hosted and no longer requires AWS Lambda.

## Rationale
- We need an application that will translate API requests from SecureX Threat Response to the third-party integration, and vice versa.
- We need an application that can be completely self contained within a virtualized container using Docker.

## Testing (Optional)

If you want to test the application you will require Docker and several dependencies from the [requirements.txt](code/requirements.txt) file:
```
pip install --upgrade --requirement code/requirements.txt
```

You can perform two kinds of testing:

- Run static code analysis checking for any semantic discrepancies and [PEP 8](https://www.python.org/dev/peps/pep-0008/) compliance:

  `flake8 code`

- Run the suite of unit tests and measure the code coverage:
  `cd code`
  `coverage run --source api/ -m pytest --verbose tests/unit/ && coverage report`

**NOTE.** If you need input data for testing purposes you can use data from the
[observables.json](code/observables.json) file.

### Building the Docker Container
In order to build the application, we need to use a `Dockerfile`.  

 1. Open a terminal.  Build the container image using the `docker build` command.

```
docker build -t tr-05-google-chronicle .
```

 2. Once the container is built, and an image is successfully created, start your container using the `docker run` command and specify the name of the image we have just created.  By default, the container will listen for HTTP requests using port 9090.

```
docker run -dp 9090:9090 --name tr-05-google-chronicle tr-05-google-chronicle
```

 3. Watch the container logs to ensure it starts correctly.

```
docker logs tr-05-google-chronicle
```

 4. Once the container has started correctly, open your web browser to http://localhost:9090.  You should see a response from the container.

```
curl http://localhost:9090
```

## Implementation Details

### Implemented Relay Endpoints

- `POST /health`
  - Verifies the Authorization Bearer JWT and decodes it to restore the
  original credentials.
  - Authenticates to the underlying external service to check that the provided
  credentials are valid and the service is available at the moment.

- `POST /observe/observables`
  - Accepts a list of observables and filters out unsupported ones.
  - Verifies the Authorization Bearer JWT and decodes it to restore the
  original credentials.
  - Makes a series of requests to the underlying external service to query for
  some cyber threat intelligence data on each supported observable.
  - Maps the fetched data into appropriate CTIM entities.
  - Returns a list per each of the following CTIM entities (if any extracted):
    - `Indicator`,
    - `Sighting`,
    - `Relationship`.
    
- `POST /version`
  - Returns the current version of the application.

### Supported Types of Observables

- `ip`
- `ipv6`
- `domain`
- `md5`
- `sha1`
- `sha256`

### JWT Payload Structure

```json
{
  "type": "<CREDENTIALS_TYPE>",
  "project_id": "<PROJECT_ID>",
  "private_key_id": "<PRIVATE_KEY_ID>",
  "private_key": "<PRIVATE_KEY>",
  "client_email": "<CLIENT_EMAIL>",
  "client_id": "<CLIENT_ID>",
  "auth_uri": "<AUTH_URI>",
  "token_uri": "<TOKEN_URI>",
  "auth_provider_x509_cert_url": "<AUTH_PROVIDER_X509_CERT_URL>",
  "client_x509_cert_url": "<CLIENT_CERT_URL>"
}
```

**NOTE**. JWT Payload Structure above matches 
[Google Developer Service Account Credential](https://developers.google.com/identity/protocols/oauth2#serviceaccount)


### CTIM Mapping Specifics

Each Google Chronicle `assets` record generates 2 CTIM `Sighting` entities
based on `assets[].firstSeenArtifactInfo.seenTime` and 
`assets[].lastSeenArtifactInfo.seenTime` 
which are used as an `.observed_time.start_time` value of a `Sighting`.
 
- Objects from `assets[].asset` are treated as a `Target` of a `Sighting`.
 
- Objects from `.assets[].firstSeenArtifactInfo.artifactIndicator` 
and `.assets[].lastSeenArtifactInfo.artifactIndicator` 
are used as `sighting.observables`.  In most cases, `artifactIndicator` field 
holds the same value as an input parameter of investigation,
but in a couple of cases it may differ:
    -  when a `subdomain` is returned as an `artifactIndicator` 
    for a `domain` investigation an observed relation
    `domain->'Supra-domain_Of'->subdomain` is created.  
    - when a `domain` is returned as an `artifactIndicator` for an `IP`
    investigation an observed relation `domain->'Resolved_To'->IP` is created.
 
Each Google Chronicle `IOC details` record generates a CTIM `Indicator` entity.

- The actual mapping here is quite straightforward. The only non-obvious piece 
of the mapping is the logic for inferring the actual values 
for the `confidence` field: 
the possible values of the `raw_confidence_score` field,
which is used as a source of `confidence`, are: 
`Low`, `Medium`, `High` or a number between `0` and `127`. 
The string values are used as-is, while the diapason of possible values
for the number is divided into 3 equal segments resulting 
in Low, Medium and High confidence. 

- `IOC details` are provided for the following types: `domain`, `ip`, `ipv6`.

Each  `Sighting` is linked to each `Indicator` with the corresponding 
CTIM `Relationship`.
