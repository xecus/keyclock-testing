# keyclock-testing

Keycloak + OAuth2 Proxy + Next.js を Docker Compose で統合したローカル検証環境です。

## 構成

```
ブラウザ
  └─ Nginx :8000
       ├─ /oauth2/*  → OAuth2 Proxy :4180  → Keycloak :8443
       ├─ /httpbin/* → httpbin :80
       └─ /          → Next.js App :3000
```

## セットアップ

### 1. 証明書の準備

Keycloak は HTTPS を使用するため、TLS 証明書が必要です。

> **注意**: `keycloak/certs/` に含まれているのはサンプル証明書です。
> 実際に使用する前に、以下の手順で自分の証明書を生成してください。

```bash
mkdir -p keycloak/certs

# 自己署名証明書の生成（開発用）
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout keycloak/certs/server.key \
  -out    keycloak/certs/server.crt \
  -subj   "/CN=keycloak" \
  -addext "subjectAltName=DNS:keycloak,DNS:localhost,IP:127.0.0.1"
```

| ファイル | 説明 |
|---|---|
| `keycloak/certs/server.crt` | TLS 証明書（公開鍵） |
| `keycloak/certs/server.key` | TLS 秘密鍵（gitignore 対象） |

### 2. 環境変数の設定

```bash
cp .env.example .env
# .env を編集して各値を設定する
```

主な設定項目:

| 変数 | 説明 |
|---|---|
| `OIDC_CLIENT_SECRET` | Keycloak で生成したクライアントシークレット |
| `OAUTH2_PROXY_COOKIE_SECRET` | Cookie 暗号化キー（下記コマンドで生成） |
| `KEYCLOAK_PUBLIC_URL` | ブラウザから Keycloak へアクセスするベース URL |
| `APP_BASE_URL` | ブラウザからアプリへアクセスするベース URL |

Cookie シークレットの生成:

```bash
python -c 'import os, base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())'
```

### 3. 起動

```bash
docker compose up -d
```

起動順序は自動で制御されます: `db` → `keycloak` → `oauth2-proxy` → `nginx`

### 4. Keycloak の初期設定

1. `http://localhost:18080` にアクセス
2. admin / admin でログイン
3. Realm `myrealm` を作成
4. Client `oauth2-proxy` を作成し、クライアントシークレットを `.env` に設定

## アクセス先

| URL | 説明 |
|---|---|
| `http://localhost:8000/` | Next.js アプリ（認証必須） |
| `http://localhost:8000/httpbin/` | httpbin（認証必須） |
| `http://localhost:18080/` | Keycloak 管理コンソール |
| `http://localhost:4180/` | OAuth2 Proxy |
