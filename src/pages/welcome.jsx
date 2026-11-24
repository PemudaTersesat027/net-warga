
import { useEffect, useState } from "react";

export default function WelcomePage() {
    const [loading, setLoading] = useState(true);
    const [started, setStarted] = useState(false);

    useEffect(() => {
        const timer = setTimeout(() => {
            setLoading(false);
        }, 2500);

        return () => clearTimeout(timer);
    }, []);

    const handleStart = () => {
        setStarted(true);
    };

    if (started) {
        return (
            <div className="min-h-screen bg-slate-50 flex items-center justify-center">
                <h1 className="text-2xl font-semibold text-slate-800">
                    Welcome to ISP Manager
                </h1>
            </div>
        );
    }

    return (
        <div className="relative min-h-screen flex flex-col items-center justify-center bg-linear-to-br from-blue-400 via-blue-200 to-blue-50 text-slate-700 overflow-hidden">

            {/* Background Decoration */}
            <div className="absolute -top-32 -left-32 w-96 h-96 rounded-full bg-blue-300/20 blur-3xl" />
            <div className="absolute -bottom-32 -right-32 w-96 h-96 rounded-full bg-emerald-300/20 blur-3xl" />

            {/* Main Content */}
            <div className="relative z-10 flex flex-col items-center">

                {/* Animated Logo */}
                <div className="relative flex items-center justify-center">

                    {/* Outer Glow */}
                    <div className="absolute w-32 h-32 rounded-full bg-emerald-300/30 blur-3xl animate-pulse" />

                    {/* Rotating Ring */}
                    <div className={`absolute w-24 h-24 rounded-3xl border-2 border-transparent border-t-emerald-400 border-r-blue-300/50 ${loading ? "animate-spin" : ""} transition-all duration-700`} />

                    {/* Logo */}
                    <div className="relative w-16 h-16 rounded-2xl bg-linear-to-br from-emerald-400 to-emerald-600 flex items-center justify-center shadow-xl shadow-emerald-500/20">
                        <span className="text-3xl font-bold text-white">I</span>
                    </div>
                </div>

                {/* Brand */}
                <div className="mt-9 text-center">
                    <h1 className="text-2xl font-bold tracking-tight text-slate-800">
                        ISP Manager
                    </h1>

                    <p className="mt-2 text-sm text-slate-500">
                        Smart Network Management System
                    </p>
                </div>

                {/* Loading / Start Button */}
                <div className="mt-10 w-56">

                    {loading ? (
                        <div className="animate-fade-in">
                            <div className="h-1.5 w-full rounded-full bg-slate-200 overflow-hidden">
                                <div className="h-full w-full rounded-full bg-linear-to-r from-emerald-400 to-blue-400 animate-loading-bar shadow-[0_0_12px_rgba(52,211,153,0.4)]" />
                            </div>

                            <p className="mt-4 text-xs text-center text-slate-400">
                                Preparing your workspace...
                            </p>
                        </div>
                    ) : (
                        <button
                            onClick={handleStart}
                            className="w-full flex items-center justify-center gap-2 py-3 px-6 rounded-xl bg-blue-500 hover:bg-blue-600 active:scale-95 text-white font-semibold text-sm shadow-lg shadow-emerald-500/20 transition-all duration-300 animate-fade-in"
                        >
                            Mulai
                            <span className="text-lg">→</span>
                        </button>
                    )}

                </div>

                {/* Footer */}
                <p className="absolute top-[calc(100vh-65px)] text-[10px] tracking-widest uppercase text-slate-400 whitespace-nowrap">
                    ISP Manager · Network Administration
                </p>

            </div>
        </div>
    );
}
