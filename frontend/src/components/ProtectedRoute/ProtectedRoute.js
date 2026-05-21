
import React from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';

const ProtectedRoute = ({ children, accessCheck }) => {
  const { user, loading } = useAuth();

  if (loading) {
    return <div>Loading...</div>;
  }

  if (!accessCheck(user)) {
    return <Navigate to="/" replace />;
  }

  return children;
};

export default ProtectedRoute;

