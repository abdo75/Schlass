import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { SetupPage } from "@/features/setup/SetupPage";
import { LoginPage } from "@/features/auth/LoginPage";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/setup" element={<SetupPage />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="*" element={<Navigate to="/setup" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
