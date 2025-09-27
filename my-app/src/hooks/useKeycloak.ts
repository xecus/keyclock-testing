import { useEffect, useState } from "react";
import Keycloak from "keycloak-js";

interface UseKeycloakReturn {
  keycloak: Keycloak | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  error: string | null;
}

export const useKeycloak = (): UseKeycloakReturn => {
  const [keycloak, setKeycloak] = useState<Keycloak | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const initKeycloak = async () => {
      try {
        const keycloakInstance = new Keycloak({
          url: "http://localhost:8080",
          realm: "myrealm",
          clientId: "myclient",
        });

        const authenticated = await keycloakInstance.init({ onLoad: "check-sso" });
        console.log({ authenticated });
        setKeycloak(keycloakInstance);
        setIsLoading(false);

        // トークンの更新を定期的に行う
        const interval = setInterval(() => {
          keycloakInstance
            .updateToken(30)
            .then((refreshed) => {
              if (refreshed) {
                console.log("Token was successfully refreshed");
                setKeycloak({ ...keycloakInstance });
              } else {
                console.log("Token is still valid");
              }
            })
            .catch((error) => {
              console.error("Failed to update token", error);
              setError("Failed to update token");
            });
        }, 10_000);

        return () => clearInterval(interval);
      } catch (err) {
        console.error("Keycloak initialization failed", err);
        setError("Keycloak initialization failed");
        setIsLoading(false);
      }
    };

    const cleanup = initKeycloak();
    return () => {
      cleanup?.then((cleanupFn) => cleanupFn?.());
    };
  }, []);

  return {
    keycloak,
    isLoading,
    isAuthenticated: keycloak?.authenticated ?? false,
    error,
  };
};