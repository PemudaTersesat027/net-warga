import { Route, Routes } from "react-router-dom";
import WelcomePage from "./pages/welcome";
import LoginPage from "./pages/auth/login";

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<WelcomePage/>} />
      <Route path="/login" element={<LoginPage />} />
    </Routes>
  )
}