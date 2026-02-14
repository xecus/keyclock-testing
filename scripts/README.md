# OIDC Authentication Examples

このディレクトリには、Keycloak OIDC Provider を使用した認証フローのサンプルスクリプトが含まれています。

## 前提条件

- Keycloak が `http://localhost:18080` で稼働していること
- Realm `myrealm` が設定されていること

## サンプル一覧

### 1. Authorization Code Flow (Confidential Client)

**ファイル**: `oidc_authcode_flow.py`

Confidential Client を使用した標準的な Authorization Code Flow の実装例です。

#### 必要な依存パッケージ

```bash
pip install authlib requests
```

#### Keycloak クライアント設定

Keycloak で以下の設定で Confidential Client を作成してください:

1. Keycloak Admin Console にログイン: http://localhost:18080/admin (admin/admin)
2. Realm `myrealm` を選択
3. **Clients** → **Create client**
   - **Client ID**: `myclient` (または任意)
   - **Client type**: `OpenID Connect`
   - **Next** をクリック
4. **Capability config**
   - **Client authentication**: `On` (Confidential Client)
   - **Authorization**: `Off`
   - **Authentication flow**: `Standard flow` をチェック
   - **Next** をクリック
5. **Login settings**
   - **Valid redirect URIs**: `http://localhost:8080/callback`
   - **Web origins**: `http://localhost:8080`
   - **Save** をクリック
6. **Credentials** タブから **Client Secret** を取得

参考: docker-compose.yaml には `oauth2-proxy` クライアントの設定例があります (Client ID: `oauth2-proxy`, Secret: `6gVL4grnkw9rMBCyS4NTLnreDNtqV1A2`)

#### 実行方法

環境変数を設定して実行:

```bash
export CLIENT_ID="myclient"
export CLIENT_SECRET="your-client-secret-here"
python3 scripts/oidc_authcode_flow.py
```

または、スクリプト内の定数を直接編集して実行:

```bash
python3 scripts/oidc_authcode_flow.py
```

#### 動作

1. ローカルに callback サーバーを起動 (`http://localhost:8080`)
2. ブラウザで Keycloak のログイン画面を開く
3. ユーザー認証後、authorization code を受け取る
4. authorization code を access token に交換
5. UserInfo エンドポイントからユーザー情報を取得
6. 取得したトークンとユーザー情報を表示

## トラブルシューティング

### Keycloak への接続エラー

Keycloak が起動しているか確認:

```bash
curl http://localhost:18080/realms/myrealm/.well-known/openid-configuration
```

### Redirect URI エラー

Keycloak のクライアント設定で、`http://localhost:8080/callback` が **Valid Redirect URIs** に登録されているか確認してください。

### Client Secret エラー

Keycloak の Client Credentials タブから正しい Secret を取得し、環境変数またはスクリプトに設定してください。
