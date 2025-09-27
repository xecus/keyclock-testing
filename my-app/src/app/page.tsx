"use client";

import styles from "./page.module.css";
import { useKeycloak } from "../hooks/useKeycloak";
import { AuthenticationPanel } from "../components/AuthenticationPanel";

export default function Home() {
  const { keycloak, isLoading, isAuthenticated, error } = useKeycloak();

  const handleRefreshToken = () => {
    keycloak?.updateToken(1_000).then((refreshed) => {
      if (refreshed) {
        console.log("Token refreshed");
      }
    });
  };

  return (
    <div className={styles.page}>
      <main className={styles.main}>
        <AuthenticationPanel
          keycloak={keycloak}
          isAuthenticated={isAuthenticated}
          isLoading={isLoading}
          error={error}
          onRefreshToken={handleRefreshToken}
        />
      </main>
    </div>
  );
}
