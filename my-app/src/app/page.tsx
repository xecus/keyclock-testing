import { headers } from 'next/headers';
import styles from "./page.module.css";

export default async function Home() {
  const headersList = headers();
  const headersObject: Record<string, string> = {};

  headersList.forEach((value, key) => {
    headersObject[key] = value;
  });

  return (
    <div className={styles.page}>
      <main className={styles.main}>
        <h1>リクエストヘッダー一覧</h1>
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
