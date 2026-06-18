// App.tsx — shell + routing. Pages live under src/pages/*.
//
// Layout (and all routes inside it) is wrapped in AuthGate, which
// uses /v1/me to decide whether to render or redirect to /login.
// Login itself is OUTSIDE the gate — otherwise we'd loop forever.
import { Navigate, Route, Routes } from "react-router-dom";
import AuthGate from "./components/AuthGate";
import Layout from "./components/Layout";
import Overview from "./pages/Overview";
import Tunnels from "./pages/Tunnels";
import Logs from "./pages/Logs";
import Login from "./pages/Login";
import Settings from "./pages/Settings";
import Tools from "./pages/Tools";

export default function App() {
  return (
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
        <Route path="logs" element={<Logs />} />
        <Route path="tools" element={<Tools />} />
        <Route path="settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/overview" replace />} />
      </Route>
    </Routes>
  );
}
