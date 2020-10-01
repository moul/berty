import React, { useState, useEffect } from 'react'
import { Linking } from 'react-native'
import { useNavigation } from '@react-navigation/native'
import { createNativeStackNavigator } from 'react-native-screens/native-stack'
import * as RawComponents from '@berty-tech/components'
import mapValues from 'lodash/mapValues'
import { Messenger } from '@berty-tech/store/oldhooks'
import { Routes } from './types'
import { messenger as messengerpb } from '@berty-tech/api/index.js'
import { createMaterialTopTabNavigator } from '@react-navigation/material-top-tabs'

function useLinking() {
	const [url, setUrl] = useState(null)
	const [error, setError] = useState()

	async function initialUrl() {
		try {
			const linkingUrl = await Linking.getInitialURL()
			if (linkingUrl) {
				setUrl(linkingUrl)
			}
		} catch (ex) {
			setError(ex)
		}
	}

	useEffect(() => {
		function handleOpenUrl(ev: any) {
			setUrl(null)
			setUrl(ev.url)
		}

		initialUrl() // for initial render

		Linking.addEventListener('url', handleOpenUrl)
		return () => Linking.removeEventListener('url', handleOpenUrl)
	}, [])

	return [url, error]
}

const DeepLinkBridge: React.FC = () => {
	const navigation = useNavigation()
	const [url, error] = useLinking()

	useEffect(() => {
		if (url && !error) {
			navigation.navigate('Modals', {
				screen: 'ManageDeepLink',
				params: { type: 'link', value: url },
			})
		}
	}, [url, error, navigation])

	return null
}

const Components = mapValues(RawComponents, (SubComponents) =>
	mapValues(SubComponents, (Component: React.FC) => (props: any) => (
		<>
			<DeepLinkBridge />
			<Component {...props} />
		</>
	)),
)

const FakeStack = createNativeStackNavigator()
export const FakeNavigation: React.FC = ({ children }) => {
	return (
		<FakeStack.Navigator screenOptions={{ headerShown: false }}>
			<FakeStack.Screen name='Fake'>{() => children}</FakeStack.Screen>
		</FakeStack.Navigator>
	)
}

const ModalsStack = createNativeStackNavigator()
export const ModalsNavigation: React.FC = () => (
	<ModalsStack.Navigator screenOptions={{ headerShown: false }}>
		<ModalsStack.Screen
			name={Routes.Modals.DeleteAccount}
			component={Components.Modals.DeleteAccount}
			options={{
				stackPresentation: 'transparentModal',
				stackAnimation: 'fade',
			}}
		/>
		<ModalsStack.Screen
			name={Routes.Modals.ManageDeepLink}
			component={Components.Modals.ManageDeepLink}
			options={{
				stackPresentation: 'transparentModal',
				stackAnimation: 'fade',
			}}
		/>
		<ModalsStack.Screen
			name={Routes.Modals.AddBetabot}
			component={Components.Modals.AddBetabot}
			options={{
				stackPresentation: 'transparentModal',
				stackAnimation: 'fade',
			}}
		/>
	</ModalsStack.Navigator>
)

const CreateGroupStack = createNativeStackNavigator()
export const CreateGroupNavigation: React.FC = () => {
	const [members, setMembers] = useState([] as any[])
	const setMember = (contact: any) => {
		if (members.find((member) => member.publicKey === contact.publicKey)) {
			return
		}
		setMembers([...members, contact])
	}
	const removeMember = (id: string) => {
		const filtered = members.filter((member) => member.publicKey !== id)
		if (filtered.length !== members.length) {
			setMembers(filtered)
		}
	}

	return (
		<CreateGroupStack.Navigator screenOptions={{ headerShown: false }}>
			<CreateGroupStack.Screen
				name={Routes.CreateGroup.CreateGroupAddMembers}
				options={{ stackPresentation: 'transparentModal' }}
			>
				{() => (
					// should use setParams ? maybe, tis weird
					<Components.Main.CreateGroupAddMembers
						members={members}
						onRemoveMember={removeMember}
						onSetMember={setMember}
					/>
				)}
			</CreateGroupStack.Screen>
			<CreateGroupStack.Screen
				name={Routes.CreateGroup.CreateGroupFinalize}
				options={{ stackPresentation: 'transparentModal' }}
			>
				{() => (
					<Components.Main.CreateGroupFinalize members={members} onRemoveMember={removeMember} />
				)}
			</CreateGroupStack.Screen>
			<CreateGroupStack.Screen
				name={'Modals'}
				component={ModalsNavigation}
				options={{ stackPresentation: 'transparentModal', stackAnimation: 'fade' }}
			/>
		</CreateGroupStack.Navigator>
	)
}

const TabStack = createMaterialTopTabNavigator() // provides swipe animation
export const TabNavigation: React.FC = () => {
	return (
		<TabStack.Navigator
			initialRouteName={Routes.Main.Home}
			tabBar={({ state }) => <Components.Main.Footer selected={state.routes[state.index].name} />}
			tabBarPosition='bottom'
		>
			<TabStack.Screen name={Routes.Main.Search} component={Components.Main.Search} />
			<TabStack.Screen name={Routes.Main.Home} component={Components.Main.Home} />
			<TabStack.Screen name={Routes.Settings.Home} component={Components.Settings.Home} />
		</TabStack.Navigator>
	)
}

const NavigationStack = createNativeStackNavigator()
export const Navigation: React.FC = () => {
	const account: any = Messenger.useAccount()
	return (
		<NavigationStack.Navigator
			initialRouteName={
				account?.displayName !== '' ? Routes.Root.Tabs : Routes.Onboarding.GetStarted
			}
			screenOptions={{ headerShown: false }}
		>
			<NavigationStack.Screen
				name={Routes.Main.ContactRequest}
				component={Components.Main.ContactRequest}
				options={{
					stackPresentation: 'transparentModal',
					stackAnimation: 'fade',
					contentStyle: { backgroundColor: 'transparent' },
				}}
			/>
			{/*<NavigationStack.Screen
				name={Routes.Main.GroupRequest}
				component={Components.Main.GroupRequest}
				options={{
					stackPresentation: 'transparentModal',
					stackAnimation: 'fade',
					contentStyle: { backgroundColor: 'transparent' },
				}}
			/>*/}
			{/* <NavigationStack.Screen name={Routes.Main.Search} component={Components.Main.Search} /> */}
			<NavigationStack.Screen
				name={Routes.Main.Scan}
				component={Components.Main.Scan}
				options={{ stackPresentation: 'transparentModal' }}
			/>
			<NavigationStack.Screen name={Routes.Chat.OneToOne} component={Components.Chat.OneToOne} />
			<NavigationStack.Screen name={Routes.Chat.Group} component={Components.Chat.MultiMember} />
			<NavigationStack.Screen
				name={Routes.Chat.OneToOneSettings}
				component={Components.Chat.OneToOneSettings}
			/>
			<NavigationStack.Screen
				name={Routes.Chat.ContactSettings}
				component={Components.Chat.ContactSettings}
			/>
			<NavigationStack.Screen
				name={Routes.Chat.MultiMemberSettings}
				component={Components.Chat.MultiMemberSettings}
			/>
			<NavigationStack.Screen
				name={Routes.Chat.MultiMemberQR}
				component={Components.Chat.MultiMemberQR}
			/>
			<NavigationStack.Screen
				name={Routes.Chat.ReplicateGroupSettings}
				component={Components.Chat.ReplicateGroupSettings}
			/>
			<NavigationStack.Screen
				name={Routes.Main.HomeModal}
				component={Components.Main.HomeModal}
				options={{
					stackPresentation: 'transparentModal',
					contentStyle: { backgroundColor: 'transparent' },
				}}
			/>
			<NavigationStack.Screen
				name={Routes.Main.RequestSent}
				component={Components.Main.RequestSent}
				options={{ stackPresentation: 'transparentModal' }}
			/>
			<NavigationStack.Screen
				name={Routes.CreateGroup.CreateGroupAddMembers}
				component={CreateGroupNavigation}
				options={{ stackPresentation: 'transparentModal' }}
			/>
			<NavigationStack.Screen name={Routes.Root.Tabs} component={TabNavigation} />
			<NavigationStack.Screen
				name={Routes.Settings.MyBertyId}
				component={Components.Settings.MyBertyId}
				options={{ stackPresentation: 'transparentModal' }}
			/>
			<NavigationStack.Screen
				name={Routes.Settings.EditProfile}
				component={Components.Settings.EditProfile}
				options={{
					stackPresentation: 'transparentModal',
					contentStyle: { backgroundColor: 'transparent' },
				}}
			/>
			<NavigationStack.Screen
				name={Routes.Settings.AppUpdates}
				component={Components.Settings.AppUpdates}
			/>
			<NavigationStack.Screen name={Routes.Settings.Help} component={Components.Settings.Help} />
			<NavigationStack.Screen
				name={Routes.Settings.FakeData}
				component={Components.Settings.FakeData}
			/>
			<NavigationStack.Screen name={Routes.Settings.Mode} component={Components.Settings.Mode} />
			<NavigationStack.Screen
				name={Routes.Settings.BlockedContacts}
				component={Components.Settings.BlockedContacts}
			/>
			<NavigationStack.Screen
				name={Routes.Settings.Notifications}
				component={Components.Settings.Notifications}
			/>
			<NavigationStack.Screen
				name={Routes.Settings.Bluetooth}
				component={Components.Settings.Bluetooth}
			/>
			<NavigationStack.Screen
				name={Routes.Settings.ServicesAuth}
				component={Components.Settings.ServicesAuth}
			/>
			<NavigationStack.Screen
				name={Routes.Settings.AboutBerty}
				component={Components.Settings.AboutBerty}
			/>
			<NavigationStack.Screen
				name={Routes.Settings.TermsOfUse}
				component={Components.Settings.TermsOfUse}
			/>
			<NavigationStack.Screen
				name={Routes.Settings.DevTools}
				component={Components.Settings.DevTools}
			/>
			<NavigationStack.Screen
				name={Routes.Settings.SystemInfo}
				component={Components.Settings.SystemInfo}
			/>
			<NavigationStack.Screen
				name={Routes.Settings.IpfsWebUI}
				component={Components.Settings.IpfsWebUI}
			/>
			<NavigationStack.Screen
				name={Routes.Settings.DevText}
				component={Components.Settings.DevText}
			/>
			<NavigationStack.Screen
				name={'Modals'}
				component={ModalsNavigation}
				options={{ stackPresentation: 'transparentModal', stackAnimation: 'fade' }}
			/>
			<NavigationStack.Screen
				name={Routes.Onboarding.GetStarted}
				component={Components.Onboarding.GetStarted}
			/>
			<NavigationStack.Screen
				name={Routes.Onboarding.SelectMode}
				component={Components.Onboarding.SelectMode}
			/>
			<NavigationStack.Screen
				name={Routes.Onboarding.Performance}
				component={Components.Onboarding.Performance}
			/>
			<NavigationStack.Screen
				name={Routes.Onboarding.Privacy}
				component={Components.Onboarding.Privacy}
			/>
		</NavigationStack.Navigator>
	)
}
