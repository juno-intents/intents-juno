import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'

export default function App() {
  return (
    <Routes>
      <Route path="/*" element={<Layout />} />
    </Routes>
  )
}
