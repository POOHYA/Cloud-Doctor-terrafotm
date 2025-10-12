import AdminLogin from './AdminLogin';
import AdminDashboard from './AdminDashboard';
import { useAuth } from '../../hooks/useAuth';

export default function AdminPage() {
  const { adminUser, loading, login, logout } = useAuth();

  if (!adminUser) {
    return <AdminLogin onLogin={login} loading={loading} />;
  }

  return <AdminDashboard adminUser={adminUser} onLogout={logout} />;
}