import { lazy, Suspense, type ReactElement } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import type { Role } from "./api/types";
import { useAuth } from "./auth/AuthContext";
import Shell from "./components/Shell";
import Admin from "./pages/Admin";
import Dashboard from "./pages/Dashboard";
import Login from "./pages/Login";
import MyTasks from "./pages/MyTasks";
import Policies from "./pages/Policies";
import Preferences from "./pages/Preferences";
import Reports from "./pages/Reports";
import RunDetail from "./pages/RunDetail";
import Scans from "./pages/Scans";
import Schedules from "./pages/Schedules";
import Targets from "./pages/Targets";

const NetworkMap = lazy(() => import("./pages/NetworkMap"));

function Guard({ min, children }: { min: Role; children: ReactElement }) {
  const { atLeast } = useAuth();
  return atLeast(min) ? children : <Navigate to="/" replace />;
}

export default function App() {
  const { user, loading } = useAuth();
  if (loading) return <div className="grid min-h-screen place-items-center text-muted">…</div>;
  if (!user || user.must_change_password) return <Login />;
  return (
    <Routes>
      <Route element={<Shell />}>
        <Route index element={<Dashboard />} />
        <Route path="tasks" element={<Guard min="USER"><MyTasks /></Guard>} />
        <Route path="scans/map" element={<Suspense fallback={<div className="p-6 text-muted">…</div>}><Guard min="USER"><NetworkMap /></Guard></Suspense>} />
        <Route path="scans" element={<Guard min="USER"><Scans /></Guard>} />
        <Route path="scans/:id" element={<RunDetail />} />
        <Route path="schedules" element={<Guard min="USER"><Schedules /></Guard>} />
        <Route path="targets" element={<Guard min="USER"><Targets /></Guard>} />
        <Route path="policies" element={<Guard min="USER"><Policies /></Guard>} />
        <Route path="reports" element={<Reports />} />
        <Route path="admin" element={<Guard min="ADMIN"><Admin /></Guard>} />
        <Route path="preferences" element={<Preferences />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
