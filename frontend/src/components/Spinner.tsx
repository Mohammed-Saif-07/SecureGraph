import { Loader2 } from "lucide-react";

interface SpinnerProps {
  size?: number;
  text?: string;
}

export function Spinner({ size = 16, text }: SpinnerProps) {
  return (
    <span className="spinner-wrapper">
      <Loader2 size={size} className="spinner-icon" />
      {text && <span className="spinner-text">{text}</span>}
    </span>
  );
}
