import logo from "@/assets/logo.png";
import { useEffect, useState } from "react";

export default function WelcomePage() {
    return (
        <div className="w-full min-h-screen grid grid-cols-2">
            <div className="w-full min-h-screen bg-linear-to-b from-blue-500 via-blue-300 to-blue-100 rounded-r-2xl shadow-blue-200">
                <div className="w-full min-h-screen items-center grid justify-center">
                    <img src={logo} alt="logo" className="h-56 w-56 bg-white rounded-lg"/>
                </div>
            </div>
            <div className="w-full min-h-screen bg-white">
                <div>Right Side</div>
            </div>
        </div>
    )
}
