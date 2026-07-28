import { Link } from "react-router-dom";
import { useAuth } from "../hooks/useAuth";

export function Navbar() {
  const { user, logout } = useAuth();

  return (
    <div className="navbar">
      <Link to="/" className="navbar__brand" style={{ textDecoration: "none" }}>
        <span className="navbar__brand-mark" />
        SENTRY-API
      </Link>
      {user && (
        <div className="navbar__right">
          <span>{user.email}</span>
          <button className="btn btn--ghost" onClick={logout}>
            Sign out
          </button>
        </div>
      )}
    </div>
  );
}
