"use client";

import React, { useState } from "react";
import { X, Smartphone, Plus, Layers, Sparkles } from "lucide-react";

interface AddDeviceModalProps {
  isOpen: boolean;
  onClose: () => void;
  onCreateDevice: (data: {
    name: string;
    manufacturer: string;
    model: string;
    android_version: string;
    color: string;
    appearance: string;
  }) => Promise<void>;
  onQuickAdd: (count: number) => Promise<void>;
}

export function AddDeviceModal({
  isOpen,
  onClose,
  onCreateDevice,
  onQuickAdd,
}: AddDeviceModalProps) {
  const [name, setName] = useState("Google Pixel 9 Pro - Lab 01");
  const [manufacturer, setManufacturer] = useState("Google");
  const [model, setModel] = useState("Pixel 9 Pro");
  const [androidVersion, setAndroidVersion] = useState("15");
  const [color, setColor] = useState("#8B5CF6");
  const [appearance, setAppearance] = useState("obsidian-slate");
  const [loading, setLoading] = useState(false);

  if (!isOpen) return null;

  const presets = [
    { label: "Google Pixel 9 Pro (Android 15)", mfg: "Google", model: "Pixel 9 Pro", ver: "15", color: "#8B5CF6", app: "obsidian-slate" },
    { label: "Samsung Galaxy S24 Ultra (Android 14)", mfg: "Samsung", model: "Galaxy S24 Ultra", ver: "14", color: "#06B6D4", app: "titanium-dark" },
    { label: "Samsung Galaxy A55 (Android 14)", mfg: "Samsung", model: "Galaxy A55 5G", ver: "14", color: "#3B82F6", app: "ice-blue" },
    { label: "OnePlus 12 (Android 14)", mfg: "OnePlus", model: "OnePlus 12", ver: "14", color: "#10B981", app: "emerald-glass" },
    { label: "Xiaomi 14 (Android 14)", mfg: "Xiaomi", model: "Xiaomi 14", ver: "14", color: "#F59E0B", app: "carbon-black" },
    { label: "Nothing Phone (2) (Android 14)", mfg: "Nothing", model: "Phone (2)", ver: "14", color: "#F43F5E", app: "glyph-white" },
  ];

  const handleSelectPreset = (p: typeof presets[0]) => {
    setName(`${p.model} - Security Lab`);
    setManufacturer(p.mfg);
    setModel(p.model);
    setAndroidVersion(p.ver);
    setColor(p.color);
    setAppearance(p.app);
  };

  const handleCreate = async () => {
    setLoading(true);
    try {
      await onCreateDevice({
        name,
        manufacturer,
        model,
        android_version: androidVersion,
        color,
        appearance,
      });
      onClose();
    } finally {
      setLoading(false);
    }
  };

  const handleQuickAdd = async (count: number) => {
    setLoading(true);
    try {
      await onQuickAdd(count);
      onClose();
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-[#111827] border border-slate-800 rounded-2xl max-w-xl w-full p-6 shadow-2xl relative">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800"
        >
          <X className="w-5 h-5" />
        </button>

        <div className="flex items-center gap-3 mb-5">
          <div className="w-10 h-10 rounded-xl bg-cyan-500/20 border border-cyan-500/40 text-cyan-400 flex items-center justify-center">
            <Smartphone className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-white">Create Virtual Android Device</h2>
            <p className="text-xs text-slate-400">
              Instantiate an independent virtual Android device inside the simulation environment.
            </p>
          </div>
        </div>

        {/* Quick Batch Add Bar */}
        <div className="p-3 mb-5 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-between">
          <div className="text-xs text-slate-300 font-medium flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-cyan-400" />
            <span>Quick Setup Presets:</span>
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => handleQuickAdd(1)}
              disabled={loading}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700 transition-colors"
            >
              Add 1 Device
            </button>
            <button
              onClick={() => handleQuickAdd(2)}
              disabled={loading}
              className="px-3.5 py-1.5 rounded-lg bg-cyan-600/20 hover:bg-cyan-600/30 text-xs font-bold text-cyan-300 border border-cyan-500/40 transition-colors"
            >
              + Add 2 Devices (Dual Lab)
            </button>
          </div>
        </div>

        {/* Preset Selector */}
        <div className="mb-4">
          <label className="text-xs font-semibold text-slate-300 mb-1.5 block">
            Choose Hardware Profile Preset:
          </label>
          <div className="grid grid-cols-2 gap-2">
            {presets.map((p, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => handleSelectPreset(p)}
                className={`p-2 rounded-lg text-left text-xs border transition-colors ${
                  model === p.model
                    ? "bg-cyan-950/40 border-cyan-500 text-white"
                    : "bg-slate-900/60 border-slate-800 text-slate-400 hover:border-slate-700"
                }`}
              >
                <div className="font-semibold">{p.mfg} {p.model}</div>
                <div className="text-[10px] text-slate-500">Android {p.ver}</div>
              </button>
            ))}
          </div>
        </div>

        {/* Custom Form Fields */}
        <div className="space-y-3 mb-6">
          <div>
            <label className="text-xs font-medium text-slate-300 mb-1 block">Device Display Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs font-medium text-slate-300 mb-1 block">Manufacturer</label>
              <input
                type="text"
                value={manufacturer}
                onChange={(e) => setManufacturer(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div>
              <label className="text-xs font-medium text-slate-300 mb-1 block">Android OS Version</label>
              <input
                type="text"
                value={androidVersion}
                onChange={(e) => setAndroidVersion(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>
        </div>

        {/* Actions */}
        <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg text-xs font-semibold text-slate-400 hover:text-white"
          >
            Cancel
          </button>
          <button
            onClick={handleCreate}
            disabled={loading}
            className="px-5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold shadow-lg shadow-cyan-600/20 transition-colors"
          >
            {loading ? "Instantiating..." : "Create Virtual Device"}
          </button>
        </div>
      </div>
    </div>
  );
}

