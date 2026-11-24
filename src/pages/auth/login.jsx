import logo from "@/assets/logo.png";
import { useEffect, useState, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import {
  Eye,
  EyeOff,
  Router,
  RefreshCw,
  ArrowRight,
  Network,
  Wifi,
} from "lucide-react";

export default function LoginPage() {
  const [devices, setDevices] = useState([]);
  const [selectedRouter, setSelectedRouter] = useState(null);
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const deviceKey = (device) => device.macAddress || device.sourceIp;

  const startDiscovery = useCallback(async () => {
    setError("");

    try {
      await invoke("start_discovery");
      setScanning(true);
    } catch (err) {
      setScanning(false);
      setError(String(err));
    }
  }, []);

  const refreshDiscovery = async () => {
    setDevices([]);
    setSelectedRouter(null);
    setScanning(false);

    try {
      await invoke("stop_discovery");
      await startDiscovery();
    } catch (err) {
      setError(String(err));
    }
  };

  useEffect(() => {
    let unlisten;
    let mounted = true;

    const initialize = async () => {
      try {
        unlisten = await listen("discovery://device", (event) => {
          if (!mounted) return;

          const { device, eventType } = event.payload;
          const key = deviceKey(device);

          if (eventType === "lost") {
            setDevices((previous) =>
              previous.filter((item) => deviceKey(item) !== key),
            );

            setSelectedRouter((previous) =>
              previous && deviceKey(previous) === key ? null : previous,
            );

            return;
          }

          setDevices((previous) => {
            const exists = previous.some((item) => deviceKey(item) === key);

            if (exists) {
              return previous.map((item) =>
                deviceKey(item) === key ? device : item,
              );
            }

            return [...previous, device];
          });
        });

        if (mounted) {
          await startDiscovery();
        }
      } catch (err) {
        if (mounted) setError(String(err));
      }
    };

    initialize();

    return () => {
      mounted = false;
      unlisten?.();
      invoke("stop_discovery").catch(console.error);
    };
  }, [startDiscovery]);

  async function testConnection() {
    const host =
      selectedRouter?.ipv4Address ||
      selectedRouter?.sourceIp;

    if (!host) {
      setError("Pilih router terlebih dahulu.");
      return;
    }

    setLoading(true);
    setError("");

    try {
      const result = await invoke("test_winbox_connection", {
        host,
        port: 8291,
      });

      setError(result);
    } catch (error) {
      console.error("Winbox connection failed:", error);
      setError(`Winbox connection failed: ${String(error)}`);
    } finally {
      setLoading(false);
    }
  }

  const handleLogin = async (event) => {
    event.preventDefault();

    if (!selectedRouter) {
      setError("Pilih router terlebih dahulu.");
      return;
    }

    setLoading(true);
    setError("");

    try {
      // TODO: Integrasikan dengan RouterClient di Rust.
      console.log({
        address: selectedRouter.ipv4Address || selectedRouter.sourceIp,
        username,
        password,
      });

      setError("RouterOS authentication belum diintegrasikan.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="min-h-screen w-full bg-white text-slate-800">
      <div className="grid min-h-screen w-full grid-cols-1 overflow-hidden bg-white lg:grid-cols-[0.85fr_1.5fr]">
        {/* LEFT: LOGIN PANEL */}
        <section className="relative flex min-h-screen flex-col justify-center overflow-hidden border-r border-slate-200 bg-white px-6 py-10 sm:px-12 lg:px-10 xl:px-14">
          {/* Background Decoration */}
          <div className="absolute -right-32 -top-32 h-80 w-80 rounded-full bg-sky-100/70 blur-3xl" />
          <div className="absolute -bottom-32 -left-32 h-80 w-80 rounded-full bg-blue-50 blur-3xl" />

          <div className="relative z-10 mx-auto w-full max-w-md">
            {/* Brand */}
            <div className="mb-10">
              <div className="mb-7 flex h-16 w-16 items-center justify-center rounded-2xl border border-slate-100 bg-white p-2 shadow-sm">
                <img
                  src={logo}
                  alt="Net Warga"
                  className="h-full w-full object-contain"
                />
              </div>

              <p className="text-xs font-bold uppercase tracking-[0.2em] text-sky-600">
                Network Management System
              </p>

              <h1 className="mt-3 text-3xl font-bold tracking-tight text-slate-900">
                Welcome back
              </h1>

              <p className="mt-3 text-sm leading-6 text-slate-500">
                Connect to your MikroTik router and manage your network
                infrastructure.
              </p>
            </div>

            {/* Selected Router */}
            <div className="mb-8 rounded-xl border border-slate-200 bg-slate-50 p-4">
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-sky-100 text-sky-600">
                  <Router size={19} />
                </div>

                <div className="min-w-0 flex-1">
                  <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
                    Selected Router
                  </p>

                  <p className="mt-1 truncate text-sm font-semibold text-slate-700">
                    {selectedRouter
                      ? selectedRouter.identity || "Unknown Router"
                      : "No router selected"}
                  </p>

                  <p className="mt-1 truncate font-mono text-xs text-slate-400">
                    {selectedRouter
                      ? selectedRouter.ipv4Address || selectedRouter.sourceIp
                      : "Select a device from the neighbors table"}
                  </p>
                </div>

                {selectedRouter && (
                  <span className="h-2 w-2 shrink-0 rounded-full bg-emerald-500" />
                )}
              </div>
            </div>

            {/* Credentials */}
            <form onSubmit={handleLogin}>
              <div className="mb-6">
                <h2 className="text-sm font-bold text-slate-800">
                  Router Credentials
                </h2>
                <p className="mt-1 text-xs text-slate-500">
                  Enter your RouterOS login credentials.
                </p>
              </div>

              <div className="space-y-5">
                <div>
                  <label className="mb-2 block text-xs font-semibold text-slate-600">
                    IP Address
                  </label>

                  <input
                    value={
                      selectedRouter?.ipv4Address ||
                      selectedRouter?.sourceIp ||
                      ""
                    }
                    placeholder="Select router from table"
                    readOnly
                    className="h-12 w-full rounded-lg border border-slate-200 bg-slate-50 px-4 text-sm text-slate-600 outline-none"
                  />
                </div>

                <div>
                  <label className="mb-2 block text-xs font-semibold text-slate-600">
                    Username
                  </label>

                  <input
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="Enter username"
                    autoComplete="username"
                    className="h-12 w-full rounded-lg border border-slate-200 px-4 text-sm outline-none transition placeholder:text-slate-300 focus:border-sky-400 focus:ring-2 focus:ring-sky-100"
                  />
                </div>

                <div>
                  <label className="mb-2 block text-xs font-semibold text-slate-600">
                    Password
                  </label>

                  <div className="relative">
                    <input
                      type={showPassword ? "text" : "password"}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="Enter router password"
                      autoComplete="current-password"
                      className="h-12 w-full rounded-lg border border-slate-200 px-4 pr-12 text-sm outline-none transition placeholder:text-slate-300 focus:border-sky-400 focus:ring-2 focus:ring-sky-100"
                    />

                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-400 transition hover:text-slate-600"
                    >
                      {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                    </button>
                  </div>
                </div>
              </div>

              {error && (
                <div className="mt-5 rounded-lg border border-red-100 bg-red-50 px-4 py-3">
                  <p className="text-xs leading-5 text-red-600">{error}</p>
                </div>
              )}

              <button
                type="submit"
                disabled={!selectedRouter || loading}
                className="mt-8 flex h-12 w-full items-center justify-center gap-2 rounded-lg bg-sky-500 px-5 text-sm font-semibold text-white shadow-lg shadow-sky-500/20 transition hover:bg-sky-600 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {loading ? "Connecting..." : "Connect to Router"}
                <ArrowRight size={17} />
              </button>
            </form>

            <button
              type="button"
              onClick={testConnection}
              disabled={!selectedRouter || loading}
              className="mt-3 flex h-11 w-full items-center justify-center gap-2 rounded-lg border border-slate-200 bg-white px-5 text-sm font-semibold text-slate-600 transition hover:border-sky-200 hover:bg-sky-50 hover:text-sky-600 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {loading ? "Testing connection..." : "Test Winbox Connection"}
            </button>

            {/* Footer */}
            <div className="mt-10 border-t border-slate-100 pt-5">
              <div className="flex items-center justify-between text-[11px] text-slate-400">
                <span>Net Warga v0.1.0</span>
                <span>© 2026 Net Warga</span>
              </div>
            </div>
          </div>
        </section>

        {/* RIGHT: NEIGHBORS TABLE */}
        <section className="flex min-h-screen flex-col bg-slate-50/60 p-5 sm:p-8 lg:p-10">
          {/* Header */}
          <header className="flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-sky-100 text-sky-600">
                <Network size={22} />
              </div>

              <div>
                <h2 className="text-lg font-bold tracking-tight text-slate-800">
                  Network Discovery
                </h2>
                <p className="text-xs text-slate-500">
                  Discover MikroTik devices on your network
                </p>
              </div>
            </div>

            <div
              className={`flex items-center gap-2 rounded-full px-3 py-2 text-xs font-semibold ${
                scanning
                  ? "bg-emerald-50 text-emerald-600"
                  : "bg-slate-200 text-slate-500"
              }`}
            >
              <span
                className={`h-2 w-2 rounded-full ${
                  scanning ? "animate-pulse bg-emerald-500" : "bg-slate-400"
                }`}
              />
              {scanning ? "Discovery Active" : "Discovery Stopped"}
            </div>
          </header>

          {/* Statistics */}
          <div className="mt-10 grid grid-cols-2 gap-4 sm:grid-cols-3">
            <div className="rounded-xl border border-slate-200 bg-white p-4">
              <div className="flex items-center gap-2 text-slate-400">
                <Router size={16} />
                <span className="text-xs font-medium">Discovered Devices</span>
              </div>
              <p className="mt-3 text-2xl font-bold text-slate-800">
                {devices.length}
              </p>
            </div>

            <div className="rounded-xl border border-slate-200 bg-white p-4">
              <div className="flex items-center gap-2 text-slate-400">
                <Wifi size={16} />
                <span className="text-xs font-medium">Protocol</span>
              </div>
              <p className="mt-3 text-2xl font-bold text-slate-800">MNDP</p>
            </div>

            <div className="col-span-2 rounded-xl border border-slate-200 bg-white p-4 sm:col-span-1">
              <div className="flex items-center gap-2 text-slate-400">
                <Network size={16} />
                <span className="text-xs font-medium">Discovery Port</span>
              </div>
              <p className="mt-3 text-2xl font-bold text-slate-800">5678</p>
            </div>
          </div>

          {/* Neighbors */}
          <div className="mt-10 flex-1">
            <div className="mb-4 flex items-center justify-between gap-3">
              <div>
                <h3 className="text-base font-bold text-slate-800">
                  Neighbors
                </h3>
                <p className="mt-1 text-xs text-slate-500">
                  Available routers detected on your network.
                </p>
              </div>

              <button
                type="button"
                onClick={refreshDiscovery}
                className="flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-semibold text-slate-600 transition hover:border-sky-200 hover:bg-sky-50 hover:text-sky-600"
              >
                <RefreshCw size={14} />
                Refresh
              </button>
            </div>

            <div className="overflow-hidden rounded-xl border border-slate-200 bg-white">
              <div className="overflow-x-auto">
                <div className="min-w-162.5">
                  {/* Table Header */}
                  <div className="grid grid-cols-[1.2fr_1fr_1fr_100px] gap-3 bg-slate-50 px-5 py-4 text-[10px] font-bold uppercase tracking-wider text-slate-400">
                    <span>Identity</span>
                    <span>Address</span>
                    <span>Board</span>
                    <span>Version</span>
                  </div>

                  {/* Device Rows */}
                  {devices.map((device) => {
                    const key = deviceKey(device);
                    const selected =
                      selectedRouter && deviceKey(selectedRouter) === key;

                    return (
                      <button
                        key={key}
                        type="button"
                        onClick={() => {
                          setSelectedRouter(device);
                          setError("");
                        }}
                        className={`grid w-full grid-cols-[1.2fr_1fr_1fr_100px] items-center gap-3 border-t border-slate-100 px-5 py-4 text-left transition ${
                          selected
                            ? "bg-sky-50 ring-1 ring-inset ring-sky-200"
                            : "hover:bg-slate-50"
                        }`}
                      >
                        <div className="min-w-0">
                          <p className="truncate text-sm font-semibold text-slate-700">
                            {device.identity || "Unknown"}
                          </p>
                          <p className="mt-1 truncate font-mono text-[10px] text-slate-400">
                            {device.macAddress || "-"}
                          </p>
                        </div>

                        <span className="truncate text-xs text-slate-600">
                          {device.ipv4Address || device.sourceIp}
                        </span>

                        <span className="truncate text-xs text-slate-600">
                          {device.board || device.platform || "-"}
                        </span>

                        <span className="truncate text-xs text-slate-500">
                          {device.version || "-"}
                        </span>
                      </button>
                    );
                  })}

                  {/* Empty State */}
                  {devices.length === 0 && (
                    <div className="flex min-h-64 flex-col items-center justify-center px-6 text-center">
                      <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-slate-100 text-slate-400">
                        <Router size={26} />
                      </div>

                      <p className="text-sm font-semibold text-slate-600">
                        No routers found
                      </p>

                      <p className="mt-2 max-w-xs text-xs leading-5 text-slate-400">
                        Waiting for MNDP announcements. Make sure your router
                        discovery is enabled.
                      </p>
                    </div>
                  )}
                </div>
              </div>
            </div>

            <div className="mt-4 flex items-center justify-between text-xs text-slate-400">
              <span>MNDP · UDP 5678</span>
              <span>{devices.length} devices found</span>
            </div>
          </div>

          {/* Footer */}
          <footer className="mt-8 border-t border-slate-200 pt-5 text-xs text-slate-400">
            Net Warga Network Management System
          </footer>
        </section>
      </div>
    </main>
  );
}
