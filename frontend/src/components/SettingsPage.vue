const sections = computed(() => [
  { id: 'general', label: t('settings.general'), icon: '⚙' },
  { id: 'personalize', label: t('settings.personalize'), icon: '🎨' },
  { id: 'other', label: t('settings.other'), icon: '📦' },
  { id: 'user', label: t('settings.user'), icon: '👤' },
  { id: 'about', label: t('settings.about'), icon: 'ℹ' },
])