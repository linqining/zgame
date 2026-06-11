import { useNavigate } from 'react-router-dom'
import {
  Lock, Users, Zap, Eye, Shuffle, ArrowRight,
  Award, TrendingUp, Globe, Clock, Sparkles, CheckCircle2, Wallet, Gamepad2
} from 'lucide-react'
import { motion, useInView, useScroll, useTransform } from 'framer-motion'
import { useRef, useState, useEffect, useCallback } from 'react'
import { ConnectButton } from '@mysten/dapp-kit-react/ui'

function FadeIn({ children, delay = 0, direction = 'up' }: { children: React.ReactNode; delay?: number; direction?: 'up' | 'down' | 'left' | 'right' }) {
  const ref = useRef(null)
  const isInView = useInView(ref, { once: true, margin: '-100px' })

  const directions = {
    up: { y: 60, x: 0 },
    down: { y: -60, x: 0 },
    left: { y: 0, x: 60 },
    right: { y: 0, x: -60 },
  }

  return (
    <motion.div
      ref={ref}
      initial={{ opacity: 0, ...directions[direction] }}
      animate={isInView ? { opacity: 1, y: 0, x: 0 } : {}}
      transition={{ duration: 1, delay, ease: [0.22, 1, 0.36, 1] }}
    >
      {children}
    </motion.div>
  )
}

function StaggerContainer({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  const ref = useRef(null)
  const isInView = useInView(ref, { once: true, margin: '-80px' })

  return (
    <motion.div
      ref={ref}
      initial="hidden"
      animate={isInView ? 'visible' : 'hidden'}
      variants={{
        hidden: {},
        visible: { transition: { staggerChildren: 0.12 } },
      }}
      className={className}
    >
      {children}
    </motion.div>
  )
}

function StaggerItem({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return (
    <motion.div
      variants={{
        hidden: { opacity: 0, y: 30 },
        visible: { opacity: 1, y: 0, transition: { duration: 0.8, ease: [0.22, 1, 0.36, 1] } },
      }}
      className={className}
    >
      {children}
    </motion.div>
  )
}

const sections = [
  { id: 'hero', label: 'Home' },
  { id: 'features', label: 'Features' },
  { id: 'value', label: 'Benefits' },
  { id: 'how', label: 'How It Works' },
  { id: 'cta', label: 'Play' },
  { id: 'footer', label: 'Footer' },
]

function ScrollNav({ activeIndex, onNavigate }: { activeIndex: number; onNavigate: (index: number) => void }) {
  return (
    <nav className="sp-scroll-nav">
      {sections.map((s, i) => (
        <button
          key={s.id}
          className={`sp-scroll-dot ${i === activeIndex ? 'active' : ''}`}
          onClick={() => onNavigate(i)}
          aria-label={s.label}
        >
          <span className="sp-scroll-label">{s.label}</span>
        </button>
      ))}
    </nav>
  )
}

export default function SecretPokerHomePage() {
  const navigate = useNavigate()
  const heroRef = useRef<HTMLElement | null>(null)
  const sectionRefs = useRef<(HTMLElement | null)[]>([])
  const [activeIndex, setActiveIndex] = useState(0)

  const { scrollYProgress } = useScroll({
    target: heroRef,
    offset: ['start start', 'end start'],
  })
  const heroOpacity = useTransform(scrollYProgress, [0, 0.8], [1, 0])
  const heroY = useTransform(scrollYProgress, [0, 1], [0, 80])

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            const index = sectionRefs.current.findIndex((el) => el === entry.target)
            if (index !== -1) {
              setActiveIndex(index)
            }
          }
        })
      },
      { threshold: 0.5 }
    )

    sectionRefs.current.forEach((el) => {
      if (el) observer.observe(el)
    })

    return () => observer.disconnect()
  }, [])

  const handleNavigate = useCallback((index: number) => {
    const el = sectionRefs.current[index]
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' })
    }
  }, [])

  const setSectionRef = useCallback((index: number) => (el: HTMLElement | null) => {
    sectionRefs.current[index] = el
  }, [])

  return (
    <div className="sp-home">
      {/* Subtle ambient particles */}
      <div className="sp-particles">
        {Array.from({ length: 12 }).map((_, i) => (
          <div
            key={i}
            className="sp-particle"
            style={{
              left: `${15 + Math.random() * 70}%`,
              top: `${15 + Math.random() * 70}%`,
              animationDelay: `${Math.random() * 15}s`,
              animationDuration: `${12 + Math.random() * 16}s`,
              opacity: 0.15 + Math.random() * 0.2,
            }}
          />
        ))}
      </div>

      {/* Hero */}
      <section className="sp-hero" ref={(el) => { heroRef.current = el; setSectionRef(0)(el) }}>
        <div className="sp-hero-bg">
          <div className="sp-hero-gradient"></div>
          <div className="sp-hero-orb sp-orb-1"></div>
          <div className="sp-hero-orb sp-orb-2"></div>
        </div>
        <motion.div
          className="sp-hero-content"
          style={{ opacity: heroOpacity, y: heroY }}
        >
          <motion.div
            className="sp-hero-badge"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, delay: 0.1 }}
          >
            <Sparkles size={14} strokeWidth={1.5} />
            <span>Mathematically Unfair to Cheaters</span>
          </motion.div>

          <motion.h1
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 1, delay: 0.2 }}
          >
            The Only Poker Room<br />
            <span className="sp-gradient-text">Where Cheating Is Impossible</span>
          </motion.h1>

          <motion.p
            className="sp-hero-desc"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, delay: 0.4 }}
          >
            Every card is encrypted before it leaves your device.
            The server cannot see your hand. Neither can we.
          </motion.p>

          <motion.div
            className="sp-hero-actions"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, delay: 0.55 }}
          >
            <motion.button
              className="sp-btn-primary sp-btn-lg"
              onClick={() => navigate('/lobby')}
              whileHover={{ scale: 1.03 }}
              whileTap={{ scale: 0.97 }}
            >
              <Zap size={18} strokeWidth={1.5} />
              Join a Table
            </motion.button>
            <motion.button
              className="sp-btn-secondary sp-btn-lg"
              onClick={() => handleNavigate(3)}
              whileHover={{ scale: 1.03 }}
              whileTap={{ scale: 0.97 }}
            >
              See How It Works
              <ArrowRight size={16} strokeWidth={1.5} />
            </motion.button>
          </motion.div>

          <motion.div
            className="sp-hero-stats"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 1, delay: 0.8 }}
          >
            <div className="sp-stat">
              <span className="sp-stat-value">Server-Blind</span>
              <span className="sp-stat-label">Your Cards Stay Hidden</span>
            </div>
            <div className="sp-stat-divider"></div>
            <div className="sp-stat">
              <span className="sp-stat-value">256-bit</span>
              <span className="sp-stat-label">End-to-End Encrypted</span>
            </div>
            <div className="sp-stat-divider"></div>
            <div className="sp-stat">
              <span className="sp-stat-value">100%</span>
              <span className="sp-stat-label">Provably Fair</span>
            </div>
          </motion.div>
        </motion.div>
      </section>

      {/* Features */}
      <section id="features" className="sp-section" ref={setSectionRef(1)}>
        <div className="sp-container">
          <FadeIn>
            <div className="sp-section-header">
              <span className="sp-section-tag">What Traditional Poker Rooms Hide From You</span>
              <h2 className="sp-section-title">Your Cards Are Invisible to Everyone but You</h2>
              <p className="sp-section-subtitle">
                In a normal poker room, the server knows every card.
                Here, it sees nothing.
              </p>
            </div>
          </FadeIn>
          <StaggerContainer className="sp-feature-grid">
            {[
              {
                icon: <Lock size={24} strokeWidth={1.5} />,
                title: 'Encrypted on Your Device',
                desc: 'Your hole cards are locked before they leave your browser. Even a server breach exposes nothing.',
                color: '#10b981',
              },
              {
                icon: <Shuffle size={24} strokeWidth={1.5} />,
                title: 'Everyone Shuffles',
                desc: 'Every player shuffles the deck. No single person — not even the platform — knows the card order.',
                color: '#3b82f6',
              },
              {
                icon: <Eye size={24} strokeWidth={1.5} />,
                title: 'Only Your Browser Can Unlock Your Hand',
                desc: 'Your private key never leaves your device. The server can never peek at your cards.',
                color: '#8b5cf6',
              },
              {
                icon: <Wallet size={24} strokeWidth={1.5} />,
                title: 'You Hold the Keys',
                desc: 'Your private key stays on your device. You control access, or safely delegate it.',
                color: '#f59e0b',
              },
            ].map((f, i) => (
              <StaggerItem key={i}>
                <motion.div
                  className="sp-feature-card"
                  whileHover={{ y: -6 }}
                  transition={{ duration: 0.4 }}
                >
                  <div className="sp-feature-icon" style={{ color: f.color }}>
                    {f.icon}
                  </div>
                  <h3>{f.title}</h3>
                  <p>{f.desc}</p>
                </motion.div>
              </StaggerItem>
            ))}
          </StaggerContainer>
        </div>
      </section>

      {/* Benefits */}
      <section id="value" className="sp-section sp-section-alt" ref={setSectionRef(2)}>
        <div className="sp-container">
          <FadeIn>
            <div className="sp-section-header">
              <span className="sp-section-tag">The House Cannot Cheat What It Cannot See</span>
              <h2 className="sp-section-title">Keep Your Edge. Keep Your Privacy.</h2>
              <p className="sp-section-subtitle">
                Lower fees. Zero server visibility. Games that run forever.
              </p>
            </div>
          </FadeIn>
          <StaggerContainer className="sp-value-grid">
            {[
              {
                icon: <Award size={28} strokeWidth={1.5} />,
                title: 'Every Hand Is Auditable',
                desc: 'Every hand leaves a cryptographic proof. Anyone can verify fairness. No trust required.',
                stat: '100%',
                statLabel: 'Auditable',
                color: '#f59e0b',
              },
              {
                icon: <Globe size={28} strokeWidth={1.5} />,
                title: 'Play Instantly, Anywhere',
                desc: 'Open your browser and play. No downloads, no accounts, no waiting.',
                stat: '0',
                statLabel: 'Downloads',
                color: '#3b82f6',
              },
              {
                icon: <TrendingUp size={28} strokeWidth={1.5} />,
                title: 'We Take Less Than 1%',
                desc: 'Traditional platforms take 2-5% per pot. We take less than 1%. That difference adds up fast.',
                stat: '<1%',
                statLabel: 'Platform Fee',
                color: '#10b981',
              },
              {
                icon: <Clock size={28} strokeWidth={1.5} />,
                title: 'No Downtime. No Maintenance.',
                desc: 'Built on decentralized infrastructure. No single point of failure means no "server maintenance" excuses.',
                stat: '24/7',
                statLabel: 'Availability',
                color: '#8b5cf6',
              },
            ].map((item, i) => (
              <StaggerItem key={i}>
                <motion.div
                  className="sp-value-card"
                  whileHover={{ y: -4 }}
                  transition={{ duration: 0.4 }}
                >
                  <div className="sp-value-header">
                    <div className="sp-value-icon" style={{ color: item.color }}>
                      {item.icon}
                    </div>
                    <div className="sp-value-stat">
                      <span className="sp-stat-number" style={{ color: item.color }}>{item.stat}</span>
                      <span className="sp-stat-desc">{item.statLabel}</span>
                    </div>
                  </div>
                  <h3>{item.title}</h3>
                  <p>{item.desc}</p>
                </motion.div>
              </StaggerItem>
            ))}
          </StaggerContainer>
        </div>
      </section>

      {/* How It Works */}
      <section id="how" className="sp-section" ref={setSectionRef(3)}>
        <div className="sp-container">
          <FadeIn>
            <div className="sp-section-header">
              <span className="sp-section-tag">Five Steps. Total Transparency.</span>
              <h2 className="sp-section-title">How We Deal a Hand Without Seeing Your Cards</h2>
              <p className="sp-section-subtitle">
                No math degree required. Here is exactly what happens, step by step.
              </p>
            </div>
          </FadeIn>
          <div className="sp-protocol-flow">
            {[
              {
                step: '01',
                title: 'Lock the Deck',
                desc: 'Each player adds a digital lock to the deck. No one can open it alone.',
                icon: <Lock size={18} strokeWidth={1.5} />,
              },
              {
                step: '02',
                title: 'Shuffle Together',
                desc: 'Every player shuffles in turn. The final order is random and unknown to anyone.',
                icon: <Shuffle size={18} strokeWidth={1.5} />,
              },
              {
                step: '03',
                title: 'Deal Face-Down',
                desc: 'Cards are dealt while locked. The server sees only encrypted data.',
                icon: <Gamepad2 size={18} strokeWidth={1.5} />,
              },
              {
                step: '04',
                title: 'Reveal When Ready',
                desc: 'When it is time to show, your browser unlocks your cards locally using your private key.',
                icon: <Eye size={18} strokeWidth={1.5} />,
              },
              {
                step: '05',
                title: 'Community Cards Open',
                desc: 'The shared cards are unlocked piece by piece by all players working together.',
                icon: <Users size={18} strokeWidth={1.5} />,
              },
              {
                step: '06',
                title: 'Verify Everything',
                desc: 'Every action leaves a proof. If anything was tampered with, anyone can spot it instantly.',
                icon: <CheckCircle2 size={18} strokeWidth={1.5} />,
              },
            ].map((s, i) => (
              <FadeIn key={i} delay={i * 0.1} direction="up">
                <div className="sp-protocol-step">
                  <div className="sp-step-number">
                    <span className="sp-step-num">{s.step}</span>
                    <span className="sp-step-icon">{s.icon}</span>
                  </div>
                  <div className="sp-step-content">
                    <h4>{s.title}</h4>
                    <p>{s.desc}</p>
                  </div>
                  {i < 5 && <div className="sp-step-line" />}
                </div>
              </FadeIn>
            ))}
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="sp-section sp-cta-section" ref={setSectionRef(4)}>
        <div className="sp-container">
          <FadeIn>
            <div className="sp-cta-content">
              <h2>No Trust Required. Just Math.</h2>
              <p>Join a table in seconds. No downloads. No hidden cards. No house edge.</p>
              <motion.button
                className="sp-btn-primary sp-btn-lg"
                onClick={() => navigate('/lobby')}
                whileHover={{ scale: 1.03 }}
                whileTap={{ scale: 0.97 }}
              >
                <Sparkles size={18} strokeWidth={1.5} />
                Start Playing Free
              </motion.button>
            </div>
          </FadeIn>
        </div>
      </section>

      <footer className="sp-footer" ref={setSectionRef(5)}>
        <div className="sp-container">
          <div className="sp-footer-content">
            <div className="sp-footer-brand">
              <span>🃏 Secret Poker</span>
              <p>Trust the math, not the house.</p>
            </div>
            <div className="sp-footer-links">
              <motion.button
                className="sp-footer-link"
                onClick={() => navigate('/lobby')}
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
              >
                Lobby
              </motion.button>
              <ConnectButton />
            </div>
            <div className="sp-footer-tech">
              <span>Built with:</span>
              <div className="sp-tech-tags">
                {['Rust', 'React', 'WebAssembly', 'Cryptography'].map((tag) => (
                  <motion.span
                    key={tag}
                    whileHover={{ scale: 1.1, y: -2 }}
                    transition={{ duration: 0.2 }}
                  >
                    {tag}
                  </motion.span>
                ))}
              </div>
            </div>
            <div className="sp-footer-ref">
              <span>Based on:</span>
              <a href="https://github.com/linqining/mental-poker-rust" target="_blank" rel="noopener noreferrer">
                Peer-reviewed mental poker cryptography
              </a>
            </div>
          </div>
        </div>
      </footer>

      <ScrollNav activeIndex={activeIndex} onNavigate={handleNavigate} />
    </div>
  )
}
