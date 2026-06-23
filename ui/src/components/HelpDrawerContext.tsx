import { createContext, useContext, useState, type ReactNode } from "react";

interface HelpDrawerContextValue {
  open: boolean;
  setOpen: (open: boolean) => void;
}

const HelpDrawerContext = createContext<HelpDrawerContextValue>({
  open: false,
  setOpen: () => {},
});

export function HelpDrawerProvider({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <HelpDrawerContext.Provider value={{ open, setOpen }}>
      {children}
    </HelpDrawerContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function useHelpDrawer() {
  return useContext(HelpDrawerContext);
}
