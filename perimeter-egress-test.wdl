version 1.0

workflow perimeter_egress_test {
  input {
    String external_bucket                 # bucket name only, NO "s3://"
    String external_prefix                 # optional key prefix, e.g. "test/" (or "")
    String external_region = "us-east-1"   # the bucket's region (MUST match)
    String docker_image                    # ECR image URI the run can pull
  }
  call attempt_external_write {
    input:
      external_bucket = external_bucket,
      external_prefix = external_prefix,
      external_region = external_region,
      docker_image = docker_image
  }
  output { File outcome = attempt_external_write.outcome }
}

task attempt_external_write {
  input {
    String external_bucket
    String external_prefix
    String external_region
    String docker_image
  }
  command <<<
    set -x
    : > outcome.txt
    echo "PATH=$PATH" | tee -a outcome.txt
    export EXT_BUCKET="~{external_bucket}"
    export EXT_PREFIX="~{external_prefix}"
    export EXT_REGION="~{external_region}"
    python3 - <<'PY' 2>&1 | tee -a outcome.txt
import os, json, re
REGION = os.environ.get("EXT_REGION") or "us-east-1"
BODY = b"perimeter egress test\n"
bucket = os.environ["EXT_BUCKET"]
key = (os.environ.get("EXT_PREFIX") or "") + "payload.txt"
print("TARGET: s3://%s/%s (region=%s)" % (bucket, key, REGION))

def via_stdlib():
    import hashlib, hmac, datetime, urllib.request, urllib.error
    def http(url, headers=None, timeout=10):
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers or {}), timeout=timeout) as r:
            return r.read().decode()
    ak = os.environ.get("AWS_ACCESS_KEY_ID"); sk = os.environ.get("AWS_SECRET_ACCESS_KEY")
    tok = os.environ.get("AWS_SESSION_TOKEN")
    if not (ak and sk):
        full = os.environ.get("AWS_CONTAINER_CREDENTIALS_FULL_URI")
        rel = os.environ.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
        hdrs = {}
        at = os.environ.get("AWS_CONTAINER_AUTHORIZATION_TOKEN")
        if at: hdrs["Authorization"] = at
        url = full or (("http://169.254.170.2" + rel) if rel else None)
        print("CRED_SOURCE:", "full_uri" if full else ("relative_uri" if rel else "NONE"))
        if url:
            try:
                d = json.loads(http(url, hdrs)); ak, sk, tok = d["AccessKeyId"], d["SecretAccessKey"], d.get("Token")
            except Exception as e:
                print("cred fetch error:", type(e).__name__, e)
    if not (ak and sk):
        print("WRITE_RESULT: ERROR: no credentials available in the container"); return
    print("HAVE_CREDS: yes (session_token=%s)" % bool(tok))
    host = "%s.s3.%s.amazonaws.com" % (bucket, REGION)
    canonical_uri = "/%s" % key
    now = datetime.datetime.utcnow()
    amzdate = now.strftime("%Y%m%dT%H%M%SZ"); datestamp = now.strftime("%Y%m%d")
    ph = hashlib.sha256(BODY).hexdigest()
    h = {"host": host, "x-amz-content-sha256": ph, "x-amz-date": amzdate}
    if tok: h["x-amz-security-token"] = tok
    signed = ";".join(sorted(h))
    canon_headers = "".join("%s:%s\n" % (k, h[k]) for k in sorted(h))
    canon_req = "\n".join(["PUT", canonical_uri, "", canon_headers, signed, ph])
    scope = "%s/%s/s3/aws4_request" % (datestamp, REGION)
    sts = "\n".join(["AWS4-HMAC-SHA256", amzdate, scope, hashlib.sha256(canon_req.encode()).hexdigest()])
    def _s(k, m): return hmac.new(k, m.encode(), hashlib.sha256).digest()
    ks = _s(_s(_s(_s(("AWS4" + sk).encode(), datestamp), REGION), "s3"), "aws4_request")
    sig = hmac.new(ks, sts.encode(), hashlib.sha256).hexdigest()
    h["Authorization"] = "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s" % (ak, scope, signed, sig)
    try:
        with urllib.request.urlopen(urllib.request.Request("https://%s%s" % (host, canonical_uri),
                                    data=BODY, method="PUT", headers=h), timeout=20) as r:
            print("WRITE_HTTP_STATUS:", r.status); print("WRITE_RESULT: SUCCEEDED")
    except urllib.error.HTTPError as e:
        body = e.read().decode()[:600]
        m = re.search(r"<Code>([^<]+)</Code>", body); code = m.group(1) if m else ""
        print("WRITE_HTTP_STATUS:", e.code); print("S3_ERROR_CODE:", code)
        print("WRITE_RESULT:", "BLOCKED (AccessDenied)" if (e.code == 403 and code == "AccessDenied") else ("OTHER_ERROR " + str(code or e.code)))
    except Exception as e:
        print("WRITE_RESULT: ERROR:", type(e).__name__, e)

via_stdlib()
PY
    echo "=== done ===" | tee -a outcome.txt
    exit 0
  >>>
  runtime {
    docker: docker_image
    cpu: 1
    memory: "2 GB"
  }
  output { File outcome = "outcome.txt" }
}
