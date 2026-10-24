import { useEffect, useState } from 'react';
import {
  Alert,
  FlatList,
  KeyboardAvoidingView,
  Modal,
  Platform,
  Pressable,
  StatusBar,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { CameraView, useCameraPermissions } from 'expo-camera';
import * as SecureStore from 'expo-secure-store';
import { PERIOD, base32Decode, parseOtpauthUri, secondsRemaining, totp } from '../lib/totp';

type Account = { id: string; label: string; issuer: string; secret: string };

const STORAGE_KEY = 'totp_accounts';

const colors = {
  bg: '#0E1116',
  card: '#171B22',
  border: '#262C36',
  text: '#E8ECF2',
  muted: '#8A93A3',
  accent: '#4ADE80',
  warn: '#F87171',
};

export default function AuthenticatorScreen() {
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [now, setNow] = useState(() => Date.now() / 1000);
  const [mode, setMode] = useState<'none' | 'scan' | 'manual'>('none');

  // Reloj: refresca 4 veces por segundo para que el cambio de ventana sea inmediato
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now() / 1000), 250);
    return () => clearInterval(id);
  }, []);

  // Cargar cuentas guardadas (en el llavero seguro del iPhone)
  useEffect(() => {
    SecureStore.getItemAsync(STORAGE_KEY).then((raw) => {
      if (raw) setAccounts(JSON.parse(raw));
    });
  }, []);

  const save = async (list: Account[]) => {
    setAccounts(list);
    await SecureStore.setItemAsync(STORAGE_KEY, JSON.stringify(list));
  };

  const addAccount = (label: string, issuer: string, secret: string) => {
    const acc: Account = { id: String(Date.now()), label, issuer, secret };
    save([...accounts, acc]);
    setMode('none');
  };

  const removeAccount = (acc: Account) => {
    Alert.alert('Eliminar cuenta', `¿Eliminar "${acc.label || acc.issuer}"?`, [
      { text: 'Cancelar', style: 'cancel' },
      { text: 'Eliminar', style: 'destructive', onPress: () => save(accounts.filter((a) => a.id !== acc.id)) },
    ]);
  };

  const remaining = secondsRemaining(now);
  const progress = remaining / PERIOD;
  const urgent = remaining <= 5;

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle="light-content" />
      <View style={styles.header}>
        <Text style={styles.title}>Authenticator</Text>
        <Text style={[styles.timer, urgent && { color: colors.warn }]}>{remaining}s</Text>
      </View>

      {/* Barra de progreso compartida: todas las cuentas cambian al mismo tiempo */}
      <View style={styles.progressTrack}>
        <View
          style={[
            styles.progressFill,
            { width: `${progress * 100}%`, backgroundColor: urgent ? colors.warn : colors.accent },
          ]}
        />
      </View>

      <FlatList
        data={accounts}
        keyExtractor={(a) => a.id}
        contentContainerStyle={{ padding: 16, gap: 12, flexGrow: 1 }}
        ListEmptyComponent={
          <View style={styles.empty}>
            <Text style={styles.emptyTitle}>Sin cuentas todavía</Text>
            <Text style={styles.emptyText}>
              Escanea el QR que genera el backend o pega el secreto Base32 a mano.
            </Text>
          </View>
        }
        renderItem={({ item }) => {
          const code = totp(item.secret, now);
          return (
            <Pressable onLongPress={() => removeAccount(item)} style={styles.card}>
              <Text style={styles.issuer}>{item.issuer || 'Sin emisor'}</Text>
              <Text style={styles.label}>{item.label}</Text>
              <Text style={[styles.code, urgent && { color: colors.warn }]}>
                {code.slice(0, 3)} {code.slice(3)}
              </Text>
            </Pressable>
          );
        }}
      />

      <View style={styles.actions}>
        <Pressable style={[styles.button, styles.primary]} onPress={() => setMode('scan')}>
          <Text style={styles.primaryText}>Escanear QR</Text>
        </Pressable>
        <Pressable style={styles.button} onPress={() => setMode('manual')}>
          <Text style={styles.buttonText}>Ingresar secreto</Text>
        </Pressable>
      </View>

      {/* Se montan solo cuando se abren, así su estado arranca limpio cada vez */}
      {mode === 'scan' && <ScanModal visible onClose={() => setMode('none')} onAdd={addAccount} />}
      {mode === 'manual' && <ManualModal visible onClose={() => setMode('none')} onAdd={addAccount} />}
    </SafeAreaView>
  );
}

type ModalProps = {
  visible: boolean;
  onClose: () => void;
  onAdd: (label: string, issuer: string, secret: string) => void;
};

function ScanModal({ visible, onClose, onAdd }: ModalProps) {
  const [permission, requestPermission] = useCameraPermissions();
  const [locked, setLocked] = useState(false);

  const handleScan = ({ data }: { data: string }) => {
    if (locked) return; // la cámara dispara varias lecturas seguidas
    setLocked(true);
    try {
      const { secret, label, issuer } = parseOtpauthUri(data);
      onAdd(label, issuer, secret);
    } catch (e: any) {
      Alert.alert('QR no válido', e.message, [{ text: 'OK', onPress: () => setLocked(false) }]);
    }
  };

  return (
    <Modal visible={visible} animationType="slide" onRequestClose={onClose}>
      <SafeAreaView style={styles.container}>
        {!permission?.granted ? (
          <View style={styles.empty}>
            <Text style={styles.emptyText}>Necesitamos acceso a la cámara para escanear el QR.</Text>
            <Pressable style={[styles.button, styles.primary, { marginTop: 16 }]} onPress={requestPermission}>
              <Text style={styles.primaryText}>Dar permiso</Text>
            </Pressable>
          </View>
        ) : (
          <CameraView
            style={{ flex: 1 }}
            facing="back"
            barcodeScannerSettings={{ barcodeTypes: ['qr'] }}
            onBarcodeScanned={handleScan}
          >
            <View style={styles.scanFrameWrap}>
              <View style={styles.scanFrame} />
              <Text style={styles.scanHint}>Apunta al QR otpauth:// del backend</Text>
            </View>
          </CameraView>
        )}
        <Pressable style={[styles.button, { margin: 16 }]} onPress={onClose}>
          <Text style={styles.buttonText}>Cancelar</Text>
        </Pressable>
      </SafeAreaView>
    </Modal>
  );
}

function ManualModal({ visible, onClose, onAdd }: ModalProps) {
  const [label, setLabel] = useState('');
  const [secret, setSecret] = useState('');

  const submit = () => {
    try {
      // También aceptamos pegar la URI completa otpauth://...
      if (secret.trim().toLowerCase().startsWith('otpauth://')) {
        const p = parseOtpauthUri(secret);
        return onAdd(label || p.label, p.issuer, p.secret);
      }
      const clean = secret.toUpperCase().replace(/[\s=-]/g, '');
      base32Decode(clean); // lanza error si no es Base32 válido
      onAdd(label || 'Cuenta manual', '', clean);
    } catch (e: any) {
      Alert.alert('Secreto inválido', e.message);
    }
  };

  return (
    <Modal visible={visible} animationType="slide" transparent onRequestClose={onClose}>
      <KeyboardAvoidingView behavior={Platform.OS === 'ios' ? 'padding' : undefined} style={styles.sheetWrap}>
        <View style={styles.sheet}>
          <Text style={styles.sheetTitle}>Agregar cuenta</Text>
          <TextInput
            style={styles.input}
            placeholder="Nombre (ej. santiago@lab)"
            placeholderTextColor={colors.muted}
            value={label}
            onChangeText={setLabel}
          />
          <TextInput
            style={[styles.input, { fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace' }]}
            placeholder="Secreto Base32 u otpauth://..."
            placeholderTextColor={colors.muted}
            autoCapitalize="characters"
            autoCorrect={false}
            value={secret}
            onChangeText={setSecret}
          />
          <View style={styles.actions}>
            <Pressable style={styles.button} onPress={onClose}>
              <Text style={styles.buttonText}>Cancelar</Text>
            </Pressable>
            <Pressable style={[styles.button, styles.primary]} onPress={submit}>
              <Text style={styles.primaryText}>Guardar</Text>
            </Pressable>
          </View>
        </View>
      </KeyboardAvoidingView>
    </Modal>
  );
}

const mono = Platform.OS === 'ios' ? 'Menlo' : 'monospace';

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: colors.bg },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'baseline',
    paddingHorizontal: 20,
    paddingTop: 12,
    paddingBottom: 10,
  },
  title: { color: colors.text, fontSize: 28, fontWeight: '700' },
  timer: { color: colors.accent, fontSize: 18, fontFamily: mono, fontWeight: '600' },
  progressTrack: { height: 4, backgroundColor: colors.border, marginHorizontal: 20, borderRadius: 2 },
  progressFill: { height: 4, borderRadius: 2 },
  card: {
    backgroundColor: colors.card,
    borderColor: colors.border,
    borderWidth: 1,
    borderRadius: 16,
    padding: 18,
  },
  issuer: { color: colors.accent, fontSize: 13, fontWeight: '600', textTransform: 'uppercase', letterSpacing: 1 },
  label: { color: colors.muted, fontSize: 14, marginTop: 2 },
  code: { color: colors.text, fontSize: 48, fontFamily: mono, fontWeight: '700', marginTop: 8, letterSpacing: 4 },
  empty: { flex: 1, alignItems: 'center', justifyContent: 'center', padding: 32 },
  emptyTitle: { color: colors.text, fontSize: 18, fontWeight: '600', marginBottom: 8 },
  emptyText: { color: colors.muted, fontSize: 15, textAlign: 'center', lineHeight: 22 },
  actions: { flexDirection: 'row', gap: 12, padding: 16 },
  button: {
    flex: 1,
    paddingVertical: 14,
    borderRadius: 12,
    alignItems: 'center',
    borderWidth: 1,
    borderColor: colors.border,
    backgroundColor: colors.card,
  },
  buttonText: { color: colors.text, fontSize: 16, fontWeight: '600' },
  primary: { backgroundColor: colors.accent, borderColor: colors.accent },
  primaryText: { color: '#0E1116', fontSize: 16, fontWeight: '700' },
  scanFrameWrap: { flex: 1, alignItems: 'center', justifyContent: 'center' },
  scanFrame: { width: 240, height: 240, borderWidth: 3, borderColor: colors.accent, borderRadius: 20 },
  scanHint: { color: '#fff', marginTop: 16, fontSize: 15, backgroundColor: '#0008', padding: 8, borderRadius: 8 },
  sheetWrap: { flex: 1, justifyContent: 'flex-end', backgroundColor: '#0009' },
  sheet: { backgroundColor: colors.bg, borderTopLeftRadius: 20, borderTopRightRadius: 20, padding: 16, paddingBottom: 32 },
  sheetTitle: { color: colors.text, fontSize: 20, fontWeight: '700', margin: 4, marginBottom: 12 },
  input: {
    backgroundColor: colors.card,
    borderColor: colors.border,
    borderWidth: 1,
    borderRadius: 12,
    color: colors.text,
    padding: 14,
    fontSize: 16,
    marginBottom: 10,
  },
});
