import React from "react";
import { StatusBar } from "expo-status-bar";
import { NavigationContainer } from "@react-navigation/native";
import { createBottomTabNavigator } from "@react-navigation/bottom-tabs";
import { View, Text, StyleSheet } from "react-native";

import { DashboardScreen } from "./src/screens/DashboardScreen";
import { AlertsScreen }    from "./src/screens/AlertsScreen";
import { IOCLookupScreen } from "./src/screens/IOCLookupScreen";
import { FeedScreen }      from "./src/screens/FeedScreen";
import { ToolkitScreen }   from "./src/screens/ToolkitScreen";
import { THEME }           from "./src/config";

const Tab = createBottomTabNavigator();

// Simple icon text (no icon library needed)
const icons: Record<string, string> = {
  Dashboard: "◈",
  Alerts:    "⚠",
  Lookup:    "⌖",
  Feed:      "◉",
  Toolkit:   "⚙",
};

export default function App() {
  return (
    <NavigationContainer>
      <StatusBar style="light" backgroundColor={THEME.bg} />
      <Tab.Navigator
        screenOptions={({ route }) => ({
          headerStyle:      { backgroundColor: THEME.bg, borderBottomWidth: 1, borderBottomColor: THEME.border },
          headerTintColor:  THEME.accent,
          headerTitleStyle: { fontWeight: "900", letterSpacing: 3, fontSize: 14 },
          tabBarStyle: {
            backgroundColor: THEME.bgCard,
            borderTopWidth:  1,
            borderTopColor:  THEME.border,
            height:          60,
            paddingBottom:   8,
          },
          tabBarActiveTintColor:   THEME.accent,
          tabBarInactiveTintColor: THEME.textDim,
          tabBarLabelStyle: { fontSize: 9, fontWeight: "700", letterSpacing: 0.5 },
          tabBarIcon: ({ focused }) => (
            <Text style={{ fontSize: 18, color: focused ? THEME.accent : THEME.textDim }}>
              {icons[route.name]}
            </Text>
          ),
          headerTitle: () => (
            <View style={styles.headerTitle}>
              <Text style={styles.headerLogo}>PHANTØM</Text>
              <Text style={styles.headerScreen}>{route.name.toUpperCase()}</Text>
            </View>
          ),
        })}
      >
        <Tab.Screen name="Dashboard" component={DashboardScreen} />
        <Tab.Screen name="Alerts"    component={AlertsScreen}    />
        <Tab.Screen name="Lookup"    component={IOCLookupScreen} />
        <Tab.Screen name="Feed"      component={FeedScreen}      />
        <Tab.Screen name="Toolkit"   component={ToolkitScreen}   />
      </Tab.Navigator>
    </NavigationContainer>
  );
}

const styles = StyleSheet.create({
  headerTitle: { alignItems: "center" },
  headerLogo:  { color: THEME.accent, fontSize: 14, fontWeight: "900", letterSpacing: 4 },
  headerScreen:{ color: THEME.textDim, fontSize: 9, letterSpacing: 2, marginTop: -2 },
});
