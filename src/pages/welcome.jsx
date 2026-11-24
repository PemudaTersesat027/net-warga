import logo from "@/assets/logo.png";
import { useEffect } from "react";
import { useNavigate } from "react-router-dom";

export default function WelcomePage() {
  const navigate = useNavigate();

  useEffect(() => {
    const timer = setTimeout(() => {
      navigate("/login", { replace: true });
    }, 2500);

    return () => clearTimeout(timer);
  }, [navigate]);

  return (
    <main className="relative flex min-h-screen w-full flex-col items-center justify-center overflow-hidden bg-[#F8FAFC]">
      <div className="pointer-events-none absolute left-1/2 top-1/2 h-125 w-125 -translate-x-1/2 -translate-y-1/2 rounded-full bg-blue-100/40 blur-[120px]" />

      <div className="relative z-10 flex flex-col items-center text-center animate-welcome">
        <div className="mb-7 flex h-72 w-72 items-center justify-center rounded-[26px] border border-slate-100 bg-white p-4 shadow-xl shadow-blue-100/50">
          <img
            src={logo}
            alt="Net Warga"
            className="h-full w-full object-contain"
          />
        </div>

        <h1 className="text-3xl font-bold tracking-tight text-slate-800">
          Net Warga
        </h1>

        <p className="mt-2 text-sm font-medium tracking-wide text-slate-400">
          NETWORK MANAGEMENT SYSTEM
        </p>

        <div className="mt-12 flex flex-col items-center gap-4">
          <div className="h-1 w-32 overflow-hidden rounded-full bg-blue-100">
            <div className="h-full w-1/2 rounded-full bg-blue-500 animate-loading" />
          </div>

          <p className="text-xs font-medium text-slate-400">
            Preparing your workspace...
          </p>
        </div>
      </div>

      <div className="absolute bottom-0 px-4 py-2 flex items-center justify-between text-center w-full h-10 bg-white border-t border-gray-400">
        <p className="text-sm text-slate-400">
          {import.meta.env.VITE_APP_COPYRIGHT}
        </p>
        <p className="text-sm text-slate-400">
          {import.meta.env.VITE_APP_NAME} v{import.meta.env.VITE_APP_VERSION}
        </p>
      </div>
    </main>
  );
}
