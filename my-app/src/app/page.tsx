import { headers } from 'next/headers';
import styles from "./page.module.css";

export default async function Home() {
  const headersList = await headers();
  const headersObject: Record<string, string> = {};

  headersList.forEach((value, key) => {
    headersObject[key] = value;
  });

  const idToken = headersList.get('x-id-token') || '';
  const logoutUrl = `http://localhost:18080/realms/myrealm/protocol/openid-connect/logout?client_id=oauth2-proxy&post_logout_redirect_uri=http://localhost:8000/oauth2/sign_out&id_token_hint=${idToken}`;

  return (
    <div className={styles.page}>
      <main className={styles.main}>
        <h1>リクエストヘッダー一覧</h1>
        <div style={{ marginTop: '20px', marginBottom: '20px' }}>
          <a
            href={logoutUrl}
            style={{
              display: 'inline-block',
              padding: '12px 24px',
              backgroundColor: '#dc3545',
              color: 'white',
              textDecoration: 'none',
              borderRadius: '5px',
              fontSize: '16px',
              fontWeight: 'bold',
              border: 'none',
              cursor: 'pointer'
            }}
          >
            ログアウト
          </a>
        </div>
        <div style={{ marginTop: '20px' }}>
          <h2>受信したヘッダー:</h2>
          <pre style={{
            backgroundColor: '#f5f5f5',
            padding: '15px',
            borderRadius: '5px',
            overflow: 'auto',
            fontSize: '14px',
            lineHeight: '1.4',
            wordWrap: 'break-word',
            whiteSpace: 'pre-wrap',
            overflowWrap: 'break-word'
          }}>
            {JSON.stringify(headersObject, null, 2)}
          </pre>
        </div>
      </main>
    </div>
  );
}
