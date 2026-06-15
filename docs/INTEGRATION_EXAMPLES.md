# Integration Examples

> **Project:** veil7  
> **Version:** 1.0  
> **Last Updated:** 2026-06-15  
> **Status:** Production-Ready

---

## Table of Contents

1. [Web Application Integration](#1-web-application-integration)
2. [REST API Integration](#2-rest-api-integration)
3. [gRPC Integration](#3-grpc-integration)
4. [Database Integration](#4-database-integration)
5. [CI/CD Pipeline Integration](#5-cicd-pipeline-integration)
6. [Cloud Services Integration](#6-cloud-services-integration)

---

## 1. Web Application Integration

### Express.js Integration

**Use Case:** Integrate veil7 verification into an Express.js web application.

**Installation:**
```bash
npm install express
```

**Example:**
```javascript
const express = require('express');
const { exec } = require('child_process');
const app = express();

app.use(express.json());

// Verify claim endpoint
app.post('/verify', (req, res) => {
  const claim = req.body.claim;
  
  exec(`veil7 verify-once "${claim}"`, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).json({ error: 'Verification failed' });
    }
    
    const verdict = JSON.parse(stdout);
    res.json(verdict);
  });
});

// Batch verify endpoint
app.post('/verify-batch', (req, res) => {
  const claims = req.body.claims;
  const files = claims.join(' ');
  
  exec(`veil7 verify-batch ${files}`, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).json({ error: 'Batch verification failed' });
    }
    
    const verdict = JSON.parse(stdout);
    res.json(verdict);
  });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
```

**Usage:**
```bash
# Start server
node server.js

# Verify claim
curl -X POST http://localhost:3000/verify \
  -H "Content-Type: application/json" \
  -d '{"claim": "Hello, World!"}'

# Batch verify
curl -X POST http://localhost:3000/verify-batch \
  -H "Content-Type: application/json" \
  -d '{"claims": ["file1.txt", "file2.txt"]}'
```

### Django Integration

**Use Case:** Integrate veil7 verification into a Django web application.

**Installation:**
```bash
pip install django
```

**Example:**
```python
# views.py
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
import subprocess
import json

@csrf_exempt
@require_POST
def verify(request):
    data = json.loads(request.body)
    claim = data['claim']
    
    result = subprocess.run(
        ['veil7', 'verify-once', claim],
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        return JsonResponse({'error': 'Verification failed'}, status=500)
    
    verdict = json.loads(result.stdout)
    return JsonResponse(verdict)

@csrf_exempt
@require_POST
def verify_batch(request):
    data = json.loads(request.body)
    claims = data['claims']
    
    result = subprocess.run(
        ['veil7', 'verify-batch'] + claims,
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        return JsonResponse({'error': 'Batch verification failed'}, status=500)
    
    verdict = json.loads(result.stdout)
    return JsonResponse(verdict)
```

**URLs:**
```python
# urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('verify', views.verify),
    path('verify-batch', views.verify_batch),
]
```

**Usage:**
```bash
# Start server
python manage.py runserver

# Verify claim
curl -X POST http://localhost:8000/verify \
  -H "Content-Type: application/json" \
  -d '{"claim": "Hello, World!"}'
```

### Spring Boot Integration

**Use Case:** Integrate veil7 verification into a Spring Boot web application.

**Installation:**
```bash
# Add to pom.xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>
```

**Example:**
```java
// VerificationController.java
@RestController
@RequestMapping("/api")
public class VerificationController {
    
    @PostMapping("/verify")
    public ResponseEntity<?> verify(@RequestBody Map<String, String> request) {
        String claim = request.get("claim");
        
        try {
            ProcessBuilder pb = new ProcessBuilder("veil7", "verify-once", claim);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            
            String output = new String(process.getInputStream().readAllBytes());
            process.waitFor();
            
            if (process.exitValue() != 0) {
                return ResponseEntity.status(500).body("Verification failed");
            }
            
            return ResponseEntity.ok(output);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error: " + e.getMessage());
        }
    }
    
    @PostMapping("/verify-batch")
    public ResponseEntity<?> verifyBatch(@RequestBody Map<String, List<String>> request) {
        List<String> claims = request.get("claims");
        
        try {
            List<String> command = new ArrayList<>();
            command.add("veil7");
            command.add("verify-batch");
            command.addAll(claims);
            
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            
            String output = new String(process.getInputStream().readAllBytes());
            process.waitFor();
            
            if (process.exitValue() != 0) {
                return ResponseEntity.status(500).body("Batch verification failed");
            }
            
            return ResponseEntity.ok(output);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error: " + e.getMessage());
        }
    }
}
```

**Usage:**
```bash
# Start server
mvn spring-boot:run

# Verify claim
curl -X POST http://localhost:8080/api/verify \
  -H "Content-Type: application/json" \
  -d '{"claim": "Hello, World!"}'
```

---

## 2. REST API Integration

### FastAPI Integration

**Use Case:** Integrate veil7 verification into a FastAPI REST API.

**Installation:**
```bash
pip install fastapi uvicorn
```

**Example:**
```python
# main.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import subprocess
import json

app = FastAPI()

class VerifyRequest(BaseModel):
    claim: str

class BatchVerifyRequest(BaseModel):
    claims: list[str]

@app.post("/verify")
async def verify(request: VerifyRequest):
    try:
        result = subprocess.run(
            ['veil7', 'verify-once', request.claim],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail="Verification failed")
        
        verdict = json.loads(result.stdout)
        return verdict
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Verification timeout")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/verify-batch")
async def verify_batch(request: BatchVerifyRequest):
    try:
        result = subprocess.run(
            ['veil7', 'verify-batch'] + request.claims,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail="Batch verification failed")
        
        verdict = json.loads(result.stdout)
        return verdict
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Batch verification timeout")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

**Usage:**
```bash
# Start server
python main.py

# Verify claim
curl -X POST http://localhost:8000/verify \
  -H "Content-Type: application/json" \
  -d '{"claim": "Hello, World!"}'
```

### Flask Integration

**Use Case:** Integrate veil7 verification into a Flask REST API.

**Installation:**
```bash
pip install flask
```

**Example:**
```python
# app.py
from flask import Flask, request, jsonify
import subprocess
import json

app = Flask(__name__)

@app.route('/verify', methods=['POST'])
def verify():
    data = request.get_json()
    claim = data['claim']
    
    try:
        result = subprocess.run(
            ['veil7', 'verify-once', claim],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode != 0:
            return jsonify({'error': 'Verification failed'}), 500
        
        verdict = json.loads(result.stdout)
        return jsonify(verdict)
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Verification timeout'}), 504
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/verify-batch', methods=['POST'])
def verify_batch():
    data = request.get_json()
    claims = data['claims']
    
    try:
        result = subprocess.run(
            ['veil7', 'verify-batch'] + claims,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode != 0:
            return jsonify({'error': 'Batch verification failed'}), 500
        
        verdict = json.loads(result.stdout)
        return jsonify(verdict)
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Batch verification timeout'}), 504
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

**Usage:**
```bash
# Start server
python app.py

# Verify claim
curl -X POST http://localhost:5000/verify \
  -H "Content-Type: application/json" \
  -d '{"claim": "Hello, World!"}'
```

### Gin Integration

**Use Case:** Integrate veil7 verification into a Gin REST API.

**Installation:**
```bash
go get -u github.com/gin-gonic/gin
```

**Example:**
```go
// main.go
package main

import (
    "encoding/json"
    "net/http"
    "os/exec"
    
    "github.com/gin-gonic/gin"
)

type VerifyRequest struct {
    Claim string `json:"claim"`
}

type BatchVerifyRequest struct {
    Claims []string `json:"claims"`
}

func verify(c *gin.Context) {
    var req VerifyRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    
    cmd := exec.Command("veil7", "verify-once", req.Claim)
    output, err := cmd.CombinedOutput()
    
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Verification failed"})
        return
    }
    
    var verdict map[string]interface{}
    json.Unmarshal(output, &verdict)
    c.JSON(http.StatusOK, verdict)
}

func verifyBatch(c *gin.Context) {
    var req BatchVerifyRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    
    args := append([]string{"verify-batch"}, req.Claims...)
    cmd := exec.Command("veil7", args...)
    output, err := cmd.CombinedOutput()
    
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Batch verification failed"})
        return
    }
    
    var verdict map[string]interface{}
    json.Unmarshal(output, &verdict)
    c.JSON(http.StatusOK, verdict)
}

func main() {
    r := gin.Default()
    r.POST("/verify", verify)
    r.POST("/verify-batch", verifyBatch)
    r.Run(":8080")
}
```

**Usage:**
```bash
# Start server
go run main.go

# Verify claim
curl -X POST http://localhost:8080/verify \
  -H "Content-Type: application/json" \
  -d '{"claim": "Hello, World!"}'
```

---

## 3. gRPC Integration

### Go gRPC Integration

**Use Case:** Integrate veil7 verification into a Go gRPC service.

**Proto Definition:**
```protobuf
// verification.proto
syntax = "proto3";

package verification;

service VerificationService {
  rpc Verify (VerifyRequest) returns (Verdict);
  rpc VerifyBatch (BatchVerifyRequest) returns (Verdict);
}

message VerifyRequest {
  string claim = 1;
}

message BatchVerifyRequest {
  repeated string claims = 1;
}

message Verdict {
  bool valid = 1;
  string transcript = 2;
}
```

**Server Implementation:**
```go
// server.go
package main

import (
    "context"
    "encoding/json"
    "log"
    "net"
    "os/exec"
    
    "google.golang.org/grpc"
    pb "verification/proto"
)

type server struct {
    pb.UnimplementedVerificationServiceServer
}

func (s *server) Verify(ctx context.Context, req *pb.VerifyRequest) (*pb.Verdict, error) {
    cmd := exec.Command("veil7", "verify-once", req.Claim)
    output, err := cmd.CombinedOutput()
    
    if err != nil {
        return nil, err
    }
    
    var verdict map[string]interface{}
    json.Unmarshal(output, &verdict)
    
    return &pb.Verdict{
        Valid: verdict["valid"].(bool),
        Transcript: verdict["transcript"].(string),
    }, nil
}

func (s *server) VerifyBatch(ctx context.Context, req *pb.BatchVerifyRequest) (*pb.Verdict, error) {
    args := append([]string{"verify-batch"}, req.Claims...)
    cmd := exec.Command("veil7", args...)
    output, err := cmd.CombinedOutput()
    
    if err != nil {
        return nil, err
    }
    
    var verdict map[string]interface{}
    json.Unmarshal(output, &verdict)
    
    return &pb.Verdict{
        Valid: verdict["valid"].(bool),
        Transcript: verdict["transcript"].(string),
    }, nil
}

func main() {
    lis, err := net.Listen("tcp", ":50051")
    if err != nil {
        log.Fatalf("failed to listen: %v", err)
    }
    
    s := grpc.NewServer()
    pb.RegisterVerificationServiceServer(s, &server{})
    
    log.Printf("server listening at %v", lis.Addr())
    if err := s.Serve(lis); err != nil {
        log.Fatalf("failed to serve: %v", err)
    }
}
```

**Client Implementation:**
```go
// client.go
package main

import (
    "context"
    "log"
    
    "google.golang.org/grpc"
    pb "verification/proto"
)

func main() {
    conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
    if err != nil {
        log.Fatalf("did not connect: %v", err)
    }
    defer conn.Close()
    
    c := pb.NewVerificationServiceClient(conn)
    
    // Verify claim
    resp, err := c.Verify(context.Background(), &pb.VerifyRequest{
        Claim: "Hello, World!",
    })
    if err != nil {
        log.Fatalf("could not verify: %v", err)
    }
    log.Printf("Verdict: valid=%v, transcript=%s", resp.Valid, resp.Transcript)
}
```

---

## 4. Database Integration

### PostgreSQL Integration

**Use Case:** Store and verify claims in PostgreSQL.

**Schema:**
```sql
CREATE TABLE claims (
    id SERIAL PRIMARY KEY,
    claim TEXT NOT NULL,
    transcript TEXT,
    verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**Example (Python):**
```python
import psycopg2
import subprocess
import json

# Connect to database
conn = psycopg2.connect(
    host="localhost",
    database="veil7",
    user="user",
    password="password"
)
cur = conn.cursor()

# Insert claim
cur.execute("INSERT INTO claims (claim) VALUES (%s) RETURNING id", ("Hello, World!",))
claim_id = cur.fetchone()[0]

# Verify claim
result = subprocess.run(
    ['veil7', 'verify-once', "Hello, World!"],
    capture_output=True,
    text=True
)

verdict = json.loads(result.stdout)

# Update claim with verdict
cur.execute(
    "UPDATE claims SET transcript = %s, verified = %s WHERE id = %s",
    (verdict['transcript'], verdict['valid'], claim_id)
)
conn.commit()

# Query verified claims
cur.execute("SELECT * FROM claims WHERE verified = TRUE")
verified_claims = cur.fetchall()
print(verified_claims)

cur.close()
conn.close()
```

### MongoDB Integration

**Use Case:** Store and verify claims in MongoDB.

**Example (Python):**
```python
from pymongo import MongoClient
import subprocess
import json

# Connect to database
client = MongoClient('mongodb://localhost:27017/')
db = client['veil7']
claims = db['claims']

# Insert claim
claim_doc = {'claim': 'Hello, World!'}
result = claims.insert_one(claim_doc)
claim_id = result.inserted_id

# Verify claim
result = subprocess.run(
    ['veil7', 'verify-once', "Hello, World!"],
    capture_output=True,
    text=True
)

verdict = json.loads(result.stdout)

# Update claim with verdict
claims.update_one(
    {'_id': claim_id},
    {'$set': {'transcript': verdict['transcript'], 'verified': verdict['valid']}}
)

# Query verified claims
verified_claims = list(claims.find({'verified': True}))
print(verified_claims)
```

### Redis Integration

**Use Case:** Cache verification results in Redis.

**Example (Python):**
```python
import redis
import subprocess
import json

# Connect to Redis
r = redis.Redis(host='localhost', port=6379, db=0)

# Verify claim
claim = "Hello, World!"
result = subprocess.run(
    ['veil7', 'verify-once', claim],
    capture_output=True,
    text=True
)

verdict = json.loads(result.stdout)

# Cache verdict
r.setex(f"verdict:{claim}", 3600, json.dumps(verdict))  # Cache for 1 hour

# Retrieve cached verdict
cached = r.get(f"verdict:{claim}")
if cached:
    verdict = json.loads(cached)
    print(verdict)
```

---

## 5. CI/CD Pipeline Integration

### GitHub Actions Integration

**Use Case:** Verify code integrity in GitHub Actions.

**Example:**
```yaml
# .github/workflows/verify.yml
name: Verify Code Integrity

on: [push, pull_request]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Install veil7
      run: |
        cargo install veil7
    
    - name: Verify source code
      run: |
        veil7 verify-batch src/main.rs src/lib.rs src/config.rs
    
    - name: Verify configuration
      run: |
        veil7 verify-file config.toml
```

### GitLab CI Integration

**Use Case:** Verify code integrity in GitLab CI.

**Example:**
```yaml
# .gitlab-ci.yml
stages:
  - verify

verify:
  stage: verify
  image: rust:latest
  script:
    - cargo install veil7
    - veil7 verify-batch src/main.rs src/lib.rs src/config.rs
    - veil7 verify-file config.toml
```

### Jenkins Integration

**Use Case:** Verify code integrity in Jenkins.

**Example:**
```groovy
// Jenkinsfile
pipeline {
    agent any
    
    stages {
        stage('Verify') {
            steps {
                sh 'cargo install veil7'
                sh 'veil7 verify-batch src/main.rs src/lib.rs src/config.rs'
                sh 'veil7 verify-file config.toml'
            }
        }
    }
}
```

---

## 6. Cloud Services Integration

### AWS Lambda Integration

**Use Case:** Deploy veil7 verification as AWS Lambda function.

**Example (Python):**
```python
# lambda_function.py
import subprocess
import json

def lambda_handler(event, context):
    claim = event['claim']
    
    result = subprocess.run(
        ['veil7', 'verify-once', claim],
        capture_output=True,
        text=True,
        timeout=30
    )
    
    if result.returncode != 0:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Verification failed'})
        }
    
    verdict = json.loads(result.stdout)
    return {
        'statusCode': 200,
        'body': json.dumps(verdict)
    }
```

**Deployment:**
```bash
# Create deployment package
zip -r lambda_function.zip lambda_function.py

# Deploy to AWS Lambda
aws lambda create-function \
  --function-name veil7-verify \
  --runtime python3.9 \
  --handler lambda_function.lambda_handler \
  --zip-file fileb://lambda_function.zip \
  --role arn:aws:iam::123456789012:role/lambda-role
```

### Google Cloud Functions Integration

**Use Case:** Deploy veil7 verification as Google Cloud Function.

**Example (Python):**
```python
# main.py
import subprocess
import json

def verify(request):
    if request.method != 'POST':
        return 'Method not allowed', 405
    
    data = request.get_json()
    claim = data['claim']
    
    result = subprocess.run(
        ['veil7', 'verify-once', claim],
        capture_output=True,
        text=True,
        timeout=30
    )
    
    if result.returncode != 0:
        return json.dumps({'error': 'Verification failed'}), 500
    
    verdict = json.loads(result.stdout)
    return json.dumps(verdict), 200
```

**Deployment:**
```bash
# Deploy to Google Cloud Functions
gcloud functions deploy veil7-verify \
  --runtime python39 \
  --trigger-http \
  --allow-unauthenticated
```

### Azure Functions Integration

**Use Case:** Deploy veil7 verification as Azure Function.

**Example (Python):**
```python
# __init__.py
import azure.functions as func
import subprocess
import json

def main(req: func.HttpRequest) -> func.HttpResponse:
    try:
        req_body = req.get_json()
        claim = req_body['claim']
        
        result = subprocess.run(
            ['veil7', 'verify-once', claim],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode != 0:
            return func.HttpResponse(
                json.dumps({'error': 'Verification failed'}),
                status_code=500,
                mimetype='application/json'
            )
        
        verdict = json.loads(result.stdout)
        return func.HttpResponse(
            json.dumps(verdict),
            status_code=200,
            mimetype='application/json'
        )
    except Exception as e:
        return func.HttpResponse(
            json.dumps({'error': str(e)}),
            status_code=500,
            mimetype='application/json'
        )
```

**Deployment:**
```bash
# Deploy to Azure Functions
func azure functionapp publish veil7-verify
```

---

## Appendix A: Best Practices

### Security Best Practices

1. **Use HTTPS:** Always use HTTPS for API endpoints
2. **Authenticate Requests:** Use API keys or OAuth for authentication
3. **Rate Limiting:** Implement rate limiting to prevent abuse
4. **Input Validation:** Validate all input before passing to veil7
5. **Timeout:** Set timeouts for all subprocess calls
6. **Error Handling:** Handle all errors gracefully
7. **Logging:** Log all verification requests and results
8. **Monitoring:** Monitor verification latency and error rates

### Performance Best Practices

1. **Batch Verification:** Use batch verification for multiple claims
2. **Parallel Verification:** Enable parallel verification for higher throughput
3. **Caching:** Cache verification results for frequently verified claims
4. **Connection Pooling:** Use connection pooling for database connections
5. **Load Balancing:** Use load balancing for high-traffic applications
6. **Auto-scaling:** Use auto-scaling for cloud deployments

---

*End of INTEGRATION_EXAMPLES.md*

*Document generated: 2026-06-15*  
*Version: 1.0*
