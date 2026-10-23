import { createTheme } from "@mui/material/styles";

export const theme = createTheme({
  palette: {
    mode: "light",
    primary: { main: "#9157FF" },
    secondary: { main: "#FF5A5A" },
    success: { main: "#16C47F" },
    warning: { main: "#FFAE1A" },
    error: { main: "#FF5A5A" },
    info: { main: "#4361EE" },
    text: { primary: "#1C1838", secondary: "#807D9C" },
    background: { default: "#ECE7F8", paper: "#FFFFFF" },
  },
  shape: { borderRadius: 14 },
  typography: {
    fontFamily: '"DM Sans", system-ui, sans-serif',
    h1: { fontFamily: '"Bricolage Grotesque", sans-serif' },
    h2: { fontFamily: '"Bricolage Grotesque", sans-serif' },
    h3: { fontFamily: '"Bricolage Grotesque", sans-serif' },
  },
  components: {
    MuiDialog: { styleOverrides: { paper: { borderRadius: 22, padding: 8, boxShadow: "0 24px 60px -20px rgba(91,63,180,.35)" } } },
    MuiDrawer: { styleOverrides: { paper: { background: "#F7F5FC", borderLeft: "1px solid #E6E1F2" } } },
    MuiTooltip: { styleOverrides: { tooltip: { background: "#1C1838", fontSize: 12, borderRadius: 8 } } },
  },
});
