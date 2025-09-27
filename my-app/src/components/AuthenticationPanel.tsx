import Keycloak from "keycloak-js";

interface AuthenticationPanelProps {
  keycloak: Keycloak | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  onRefreshToken: () => void;
}

export const AuthenticationPanel = ({
  keycloak,
  isAuthenticated,
  isLoading,
  error,
  onRefreshToken,
}: AuthenticationPanelProps) => {
  if (isLoading) {
    return <p>Loading...</p>;
  }

  if (error) {
    return <p style={{ color: "red" }}>Error: {error}</p>;
  }

  return (
    <div>
      <div style={{ marginBottom: "16px" }}>
        <button
          onClick={() => keycloak?.login()}
          disabled={isAuthenticated}
        >
          LOGIN
        </button>
        <button
          onClick={() => keycloak?.logout({ redirectUri: window.location.origin })}
          disabled={!isAuthenticated}
          style={{ marginLeft: "8px" }}
        >
          LOGOUT
        </button>
        <button
          onClick={onRefreshToken}
          disabled={!isAuthenticated}
          style={{ marginLeft: "8px" }}
        >
          Refresh
        </button>
      </div>
      <p>
        Status: {isAuthenticated ? "Authenticated" : "Not Authenticated"}
      </p>
      {keycloak?.token && (
        <div style={{ marginTop: "16px" }}>
          <p>Access Token:</p>
          <textarea
            readOnly
            value={keycloak.token}
            style={{
              width: "100%",
              height: "120px",
              fontSize: "12px",
              fontFamily: "monospace",
              padding: "8px",
              border: "1px solid #ccc",
              borderRadius: "4px",
              resize: "vertical",
              wordBreak: "break-all"
            }}
          />
        </div>
      )}
    </div>
  );
};