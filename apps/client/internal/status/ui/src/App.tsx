// App.tsx — shell + routing. Pages live under src/pages/*.
//
// Layout (and all routes inside it) is wrapped in AuthGate, which
// uses /v1/me to decide whether to render or redirect to /login.
// Login itself is OUTSIDE the gate — otherwise we'd loop forever.
//
// ConsoleLockGate wraps everything, login included: a visitor from another
// machine unlocks the console before anything else (see its header).
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import AuthGate from "./components/AuthGate";
import ConsoleLockGate from "./components/ConsoleLockGate";
import Layout from "./components/Layout";
import Overview from "./pages/Overview";
import Tunnels from "./pages/Tunnels";
import TunnelNew from "./pages/TunnelNew";
import Mesh from "./pages/Mesh";
import Logs from "./pages/Logs";
import Login from "./pages/Login";
import Settings from "./pages/Settings";
import Tools from "./pages/Tools";

// Keeps ?declare_port=… on the way through, so an old link from 工具 still
// opens the declaration form prefilled.
function ServicesMoved() {
  const { search } = useLocation();
  return <Navigate to={`/mesh/services${search}`} replace />;
}

export default function App() {
  return (
    <ConsoleLockGate>
      <Routes>
        <Route path="login" element={<Login />} />
        <Route
          element={
            <AuthGate>
              <Layout />
            </AuthGate>
          }
        >
          <Route index element={<Navigate to="/overview" replace />} />
          <Route path="overview" element={<Overview />} />
          <Route path="tunnels" element={<Tunnels />} />
          {/* The create flow is a PAGE, not a dialog the list opens: it has
              steps, it is linked to from 工具 and 服务, and it has to survive a
              reload. Nested under /tunnels so the sidebar keeps 隧道 selected
              (Layout reads the first path segment). */}
          <Route path="tunnels/new" element={<TunnelNew />} />
          {/* 组网 is one menu entry with three tabs, each with its own URL so a
              tab can be linked to (工具's port scanner lands on 服务) and
              survives a reload. Same shape as the web console's 组网配置. */}
          <Route path="mesh" element={<Mesh />} />
          <Route path="mesh/services" element={<Mesh />} />
          <Route path="mesh/routing" element={<Mesh />} />
          {/* 服务 was a top-level menu entry until 2026-09-16. It is a mesh
              object — declared here, confirmed by an admin, matched by svc:
              access rules — so it now lives under 组网, as it does in the web
              console. The old address still works, query string included. */}
          <Route path="services" element={<ServicesMoved />} />
          <Route path="logs" element={<Logs />} />
          <Route path="tools" element={<Tools />} />
          <Route path="settings" element={<Settings />} />
          <Route path="*" element={<Navigate to="/overview" replace />} />
        </Route>
      </Routes>
    </ConsoleLockGate>
  );
}
